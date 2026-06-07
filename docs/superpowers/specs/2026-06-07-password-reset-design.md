# Password-Reset (Forgot Password) — Design

**Date:** 2026-06-07
**Status:** Approved, implementing
**Repos:** `fendix-backend` (Django/DRF) + `fendix_frontend` (Next.js 16 / React 19)

## Problem

The login page has a "Forgot password?" button ([login/page.tsx:215](../../../../fendix_frontend/app/login/page.tsx)) that is a dead `<button type="button">` with no handler — clicking it does nothing. There is no `/forgot-password` or `/reset-password` route, and the backend `AuthViewSet` has no password-reset endpoint. The whole flow is missing on both ends.

## Decisions (locked)

- **Token:** Django `default_token_generator` (`PasswordResetTokenGenerator`) — cryptographic, one-time-use (binds the password hash, so it dies on password change), invalidate-on-use for free. **No DB model.**
- **Link, not OTP:** emailed reset is a clickable link `${FRONTEND_URL_BASE}/reset-password?uid=<b64 uid>&token=<token>`. (Considered TwiScope's 6-digit OTP model; rejected — smaller value space, brute-forceable, needs a DB table. We borrow only TwiScope's *async-email mechanism*, not its token model or its security posture.)
- **Post-reset:** redirect to `/login` (no auto-login, no cookie-setting on the reset endpoints).
- **Token TTL:** 1 hour (`PASSWORD_RESET_TIMEOUT = 3600`).
- **Email:** async via Celery (`.delay()`), mirroring `billing/tasks.py` + TwiScope's `send_reset_email_async`.
- **Anti-enumeration:** the request endpoint ALWAYS returns the same 200, whether or not the email exists (mirrors the existing `LoginSerializer` constant-time pattern). This is the explicit fix vs. TwiScope, which leaks email existence.
- **Scope:** full vertical slice, both repos.

## Section 1 — API contract

`POST /api/auth/password-reset` — request a link
- Request: `{ "email": "user@example.com" }`
- Response: ALWAYS `200 {"detail": "If that email exists, a reset link has been sent."}`
- Side effect: if the email matches an active user, enqueue an email with the reset link.
- Throttle: `password_reset` scope, `5/hour` per IP.

`POST /api/auth/password-reset/confirm` — set the new password
- Request: `{ "uid": "<b64 user id>", "token": "<token>", "password": "<new password>" }`
- Success: `200 {"detail": "Password reset. You can now sign in."}`
- Errors (`400`): `{"token": ["This reset link is invalid or has expired."]}` for bad/expired/used token; `{"password": ["<msg>"]}` for weak passwords (Django `validate_password`).
- No cookies set, no auto-login.

## Section 2 — Backend implementation (`fendix-backend`)

1. **`accounts/serializers.py`**
   - `PasswordResetRequestSerializer`: `email` only; `validate_email` normalizes (`.lower().strip()`); does NOT reveal existence.
   - `PasswordResetConfirmSerializer`: `uid`, `token`, `password`; `validate()` decodes uid → loads user → `default_token_generator.check_token(user, token)`; raises `400 {"token": [...]}` on failure; `validate_password` runs Django validators; `save()` does `user.set_password()` + `user.save()` (rotates hash → invalidates token).

2. **`accounts/tasks.py`** (new) — `@shared_task(bind=True, max_retries=3, default_retry_delay=60)` `send_password_reset_email(self, user_id: str, reset_url: str, email: str)`. Serializable args only (ids/strings — JSON serializer, confirmed by TwiScope's `CELERY_TASK_SERIALIZER="json"`). Builds `EmailMultiAlternatives`, `render_to_string` for `.txt` + `.html`, `attach_alternative`, `self.retry(exc=exc)` on failure. (Retry config is the improvement over TwiScope's bare `@shared_task`.)

3. **`accounts/templates/accounts/email/password_reset.{txt,html}`** (new) — plain-text + HTML, matching `billing/templates/billing/email/` convention.

4. **`accounts/views.py`** — two `@action`s on `AuthViewSet`, both `detail=False`, `methods=["post"]`, `permission_classes=[AllowAny]`, `auth=[]`, with `@extend_schema`:
   - `password_reset` (`url_path="password-reset"`, `PasswordResetRequestThrottle`): validate email; if user exists, build `uid`+`token`, construct `${FRONTEND_URL_BASE}/reset-password?uid=&token=`, call `send_password_reset_email.delay(...)`; ALWAYS return the same 200.
   - `password_reset_confirm` (`url_path="password-reset/confirm"`): run confirm serializer, `save()`, return 200.
   - Add both to `get_serializer_class` mapping.

5. **`config/settings/base.py`** — add real `FRONTEND_URL_BASE = os.getenv("FRONTEND_URL_BASE", "http://localhost:3000")` (also fixes the latent bug where `scanning/notifications.py` silently fell back to localhost because the attribute was never set), and `PASSWORD_RESET_TIMEOUT = 3600`.

6. **`config/settings/_helpers/rest_framework_config.py`** — add `"password_reset": "5/hour"` to `DEFAULT_THROTTLE_RATES`; add the matching `ScopedRateThrottle` subclass in `accounts/views.py`.

7. **`accounts/tests/test_auth.py`** — `TestPasswordReset` / `TestPasswordResetConfirm` (pytest + `APIClient`):
   - request for known email enqueues mail; request for UNKNOWN email returns identical 200 and enqueues nothing (anti-enumeration);
   - confirm with valid token resets password + lets the user log in;
   - confirm with expired/invalid/reused token → 400;
   - weak password → 400;
   - token dies after the password changes (one-time-use).
   - Use `CELERY_TASK_ALWAYS_EAGER=True` + `mailoutbox` for the task body; mock `.delay` in view tests.

## Section 3 — Frontend implementation (`fendix_frontend`)

1. **`app/lib/api.ts`** (after `register`): `requestPasswordReset(email)` → `POST /auth/password-reset`; `confirmPasswordReset(uid, token, password)` → `POST /auth/password-reset/confirm`. Both `apiFetch<void>`, mirroring `login`.

2. **`app/forgot-password/page.tsx`** — email-only form, mirrors the login shell (AuthBranding, decor, `max-w-sm` card, same input/label/error/submit classes, `Magnetic`, `useToast`). On submit → `requestPasswordReset(email)` → ALWAYS show the same success state ("If that email exists, we've sent a reset link"). No `useSearchParams`, no Suspense needed. "Back to sign in" link.

3. **`app/reset-password/page.tsx`** — reads `?uid=` + `?token=` via `useSearchParams` (wrapped in `<Suspense>`). Fields: new password + confirm; reuse `PasswordStrength` from signup + eye toggle. `validate()`: length ≥ 8 and match. On submit → `confirmPasswordReset(...)`:
   - success → toast + `router.push("/login")`
   - `400 {token}` → inline "invalid or expired" + "Request a new link" → `/forgot-password`
   - `400 {password}` → inline under password field (existing field-error mapping)
   - missing `uid`/`token` in URL → show "invalid link" state immediately, no API call.
   All inputs get `id`/`name`/`htmlFor`.

4. **Wire the dead button** — [login/page.tsx:215] convert the inert `<button>` into `<Link href="/forgot-password">`. (This is the original bug.)

## Section 4 — Testing & verification

- **Backend:** `pytest accounts/tests/test_auth.py` green; the 6 scenarios above.
- **Frontend:** new `tests/pages/forgot-password.test.tsx` + `reset-password.test.tsx` mirroring login/signup test skeletons (`renderWithToast`, `mockRoute`, `json`, `pushMock`, `useSearchParams` spy for uid/token). Cover: validation, success path, anti-enumeration UI, invalid-token state, weak-password inline error.
- **Gate:** backend pytest green; frontend `tsc --noEmit` + `eslint` (0 errors) + `vitest` (all pass) + `next build` clean.

## Out of scope (future)

- Rate-limiting confirm attempts beyond the per-IP request throttle.
- HTML email design polish / shared email base template.
- "Resend link" cooldown UX.
