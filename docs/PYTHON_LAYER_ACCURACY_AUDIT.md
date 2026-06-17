# fendix Python Analysis Layer — Accuracy Audit (Definitive Report)

**Scope:** `ast_analyzer.py`, `route_extractor.py`, `spec_parser.py`, `deps.py`, `engine.py`
**Engine path:** `/Users/asaied/WorkDir/Fendix/fendix-engine/python` · Runtime Python 3.14.5 · invoked via `echo '<ScanRequest>' | python3 engine.py`, `checks=["injection"|"auth"|"deps"]`
**Method:** Every finding reproduced from fresh `/tmp` fixtures and adversarially re-verified by a second independent agent. `code_path` must be a **directory** (`ASTAnalyzer.run` uses `os.walk`; a single file silently yields `total:0`). The correct AST/taint check key is `"injection"`, not `"sast"`.

---

## 1. Executive Summary

The taint engine is **structurally sound on the happy path** — `request.args`/`request.form`/`request.GET` → `os.system`/`cursor.execute`/`requests.get` fires correctly with `taint_chain` + `reachable:true` + route binding — but its **detection surface is dangerously narrow at the edges**. Of the reproduced issues, **24 are confirmed bugs** (the engine's own docstrings/tests/comments claim coverage it does not deliver) and **16 are coverage gaps** (never claimed; FNs an attacker exploits), plus **9 false-positive sources** and **5 robustness/contract defects**. The dominant theme is **import-shape and source-attribute brittleness**: aliased/`from`-imported sinks (`import os as _o`, `from pickle import loads`), un-modeled sources (cookies, headers, `request.FILES`, FastAPI typed params), and an un-handled `+=` accumulator all silently zero out real RCE/SQLi findings.

**The single most important fix** is the **augmented-assignment false negative** (`cmd = "ping "; cmd += request.args['host']; os.system(cmd)`): a missing `visit_AugAssign` lets a stale constant binding **actively sanitize** a real command/SQL injection across all three top sink families with empty stderr — a total, silent miss on one of the most common injection idioms (CRITICAL-class impact, verified HIGH). Closely behind it: wiring `_module_aliases` into the `os.system`/`subprocess`/SSRF sink predicates (the map is already populated but never consulted there), and adding a single `visit_ImportFrom` to catch `from pickle/yaml/os/subprocess/requests/urllib import …`.

---

## 2. Confirmed Bugs

*Engine claims/implies coverage (via docstring, comment, sibling code, or shipped test) but does not deliver. Ordered by verified severity.*

### CRITICAL

**1. Augmented assignment (`+=`) after constant init silently sanitizes cmdi/SQLi sinks**
*Severity: HIGH (claimed CRITICAL) · `ast_analyzer.py` — missing `visit_AugAssign`; `visit_Assign:995`, `_cmdi_arg_is_dangerous:1033`, `_is_sql_injection:1079`*
Repro: `cmd="ping "; cmd+=request.args['host']; os.system(cmd)` → `{"done":true,"total":0}` (empty stderr). The `=`-concat control fires with full chain.
Root cause: There is **no `visit_AugAssign`** (grep confirms). `visit_Assign` records `cmd → ast.Constant("ping ")`; the `+=` node falls through `generic_visit` and never updates the binding. At the sink, `_cmdi_arg_is_dangerous`/`_is_sql_injection` resolve `cmd` to the stale `ast.Constant` and return "safe." The stale constant **overrides** the tainted append. Same silence on `subprocess.run(cmd, shell=True)` and `cursor.execute(q)`. This is a bug, not a gap: `ast_analyzer.py:325-328` (TASK-114) documents intra-function taint "through one or more intra-function assignments" and ships `test_multi_step_assignment_*` for the `=` form.
Fix: Add `visit_AugAssign` that rebinds `node.target.id` to a synthesized `ast.BinOp(left=prior_or_Name, op=node.op, right=node.value)` (or the AugAssign node itself), then `generic_visit`.

### HIGH

**2. FastAPI/Starlette typed function-arg params are never taint sources**
*HIGH · `_references_request_input:1601` / `visit_FunctionDef:984` / `_REQUEST_INPUT_ATTRS:1577`*
Repro: `@app.get("/f")\ndef h(f: str): return os.path.join("/data", f)` → `total:0`. Flask control `request.args.get` fires `total:1` with chain+reachable+route.
Root cause: Only `request.<attr>`/`req.<attr>` subtrees are sources. `visit_FunctionDef` pushes a scope but never seeds `node.args.args` as sources, even when the function is a bound route handler. Because `os.path.*` is gated on `chain is not None` (line 959) it is **fully suppressed**; `os.system`/SSRF/`open` still fire but lose chain/reachable/route. The module docstring (1574-1580) and "Proven Path v1" comments explicitly claim FastAPI/Starlette route→handler→source→sink coverage.
Fix: In `visit_FunctionDef`, when `self._route_table.for_function(node.name)` resolves, seed each parameter name (`args.args/posonlyargs/kwonlyargs`) into the scope as a synthetic source; make `_references_request_input`/`_trace_to_source` treat a Name resolving to such a seed as a source.

**3. `request.cookies` is not a recognized taint source**
*MEDIUM (claimed HIGH) · `_REQUEST_INPUT_ATTRS:1577-1580`*
Repro: `os.path.join("/data", request.cookies["f"])` → `total:0`; identical `request.args["f"]` fires. Also misses `request.cookies.get("f")` and Django `request.COOKIES["x"]`. On non-gated sinks the cookie case fires but drops chain/reachable.
Root cause: `cookies`/`COOKIES` absent from the attr set; only `headers` is the documented intentional exclusion. Downgraded to MEDIUM because direct cookie→sink flows are materially rarer and detection loss is total only on the `os.path.*` family.
Fix: Add `"cookies"` and `"COOKIES"` to `_REQUEST_INPUT_ATTRS`.

**4. `request.headers` value is not a taint source (only the auth-trust `if` is handled)**
*HIGH · `_REQUEST_INPUT_ATTRS:1577` (`headers` excluded per comment 1575)*
Repro: `os.path.join("/d", request.headers.get("X-File"))` → `total:0`. Also Django `request.META[...]`.
Root cause: The comment defers headers to `_is_request_header_trust`, but that helper only matches `if request.headers.get(...)` used as an **auth `if`-test** (PY_AUTH_HEADER_TRUST) — not header **values** flowing to injection sinks. The exclusion conflates "header trust for auth" with "header value as source." `os.system`/SQL still fire but without chain/reachable.
Fix: Add `"headers"` (and Django `META`) to `_REQUEST_INPUT_ATTRS`, or add a separate header-value source path; the auth-trust `if` check is orthogonal and can coexist.

**5. `request.get_json()`/`get_data()` method-call body accessors are not sources**
*HIGH · `_references_request_input:1601` + `_REQUEST_INPUT_ATTRS:1577`*
Repro: `os.path.join("/d", request.get_json()["f"])` → `total:0`; the property form `request.json["f"]` fires `total:1` with chain.
Root cause: The set contains attribute names `json`/`data`, but `request.get_json()` is an `ast.Call` whose subscript `.value` is a Call (not an Attribute), and `get_json`/`get_data` aren't attrs in the set — so neither branch matches. `get_json()` is Flask's canonical documented body accessor (`request.json` is just its property alias). (Note: `get_data()` returns bytes so the subscript example is contrived, but it is still wrongly excluded.)
Fix: In `_references_request_input`, recognize `request.<m>(...)` where `m ∈ {get_json, get_data}` and treat a Subscript/Attribute whose `.value` chain bottoms out in such a Call as tainted.

**6. Django `request.FILES` (uppercase) is not a source**
*HIGH (claimed MEDIUM) · `_REQUEST_INPUT_ATTRS:1577`*
Repro: `os.path.join("/d", request.FILES["f"].name)` → `total:0`; `request.POST["f"]`/Flask `request.files["f"]` fire HIGH+reachable. `.name` is irrelevant — bare `request.FILES["f"]` is also missed.
Root cause: The set has lowercase `files` (Flask) but Django spells it `FILES` (uppercase, alongside `GET`/`POST` which **are** uppercased in the set). Exact-string membership → miss. `request.FILES` is the canonical Django upload source; path traversal via attacker-controlled filename is high-prevalence.
Fix: Add `"FILES"` to the frozenset (keep lowercase `files`).

**7. `os.path.*` sinks fully suppressed for unrecognized sources**
*MEDIUM (claimed HIGH) · `visit_Call` path-traversal branch, gate at line 959 `if sink_name.startswith("os.path.") and chain is None: pass`*
Repro: `os.path.join("/data", request.cookies["f"])` → `total:0`; `os.path.expanduser`/`abspath` likewise. `open(request.cookies["f"])` fires (without chain), proving the source reaches the sink and only the `os.path.*` gate suppresses it.
Root cause: The gate (intended to avoid FPs on library code over fixed paths) is acceptable **only if source coverage is complete**. Combined with the source gaps (3-6), it converts every `os.path.*` traversal fed by an unseen source into a hard FN. Downgraded to MEDIUM: requires both an unrecognized source **and** an `os.path.*` sink with no intervening `open`/`Path`/`send_file`.
Fix: Close the upstream source gaps; the line-959 gate is fine once sources are complete.

**8. SSRF missed when `requests` is aliased or its method is `from`-imported**
*HIGH · `_ssrf_sink_name:1329` / `_is_ssrf:1293`*
Repro: `import requests as r; r.get(url)` → `total:0`; `from requests import get; get(url)` → `total:0`; baseline `requests.get` fires HIGH+reachable.
Root cause: `_ssrf_sink_name` hard-codes `func.value.id == "requests"` and **never consults `self._module_aliases`** (which `visit_Import` does populate with `r→requests`). The `from`-import yields a bare `ast.Name`, failing the `isinstance(node.func, ast.Attribute)` guard in `_is_ssrf`.
Fix: `base = self._module_aliases.get(func.value.id, func.value.id)` then compare `== "requests"`; add `visit_ImportFrom` to track `from requests import get/post`.

**9. `os.system`/`os.popen` missed when `os` is aliased or `system` is `from`-imported**
*HIGH (claimed CRITICAL) · `visit_Call` os.system/os.popen branches (~618-657)*
Repro: `import os as _o; _o.system(cmd)` → `total:0`; `from os import system; system(cmd)` → `total:0`; `import os as o; o.popen(cmd)` → `total:0`; baseline fires HIGH+reachable.
Root cause: Both branches require `node.func.value.id == "os"` with no `_module_aliases` lookup; the from-import is a bare Name. **Decisive control:** `import pickle as p; p.loads(...)` *does* fire (because `_is_pickle_load`/`_is_unsafe_yaml_load` resolve through the alias map) — proving alias resolution exists and was simply never wired into the os branches. Severity set to HIGH (the engine's own `os.system` baseline emits HIGH/CWE-78, not CRITICAL).
Fix: Resolve receiver via `_module_aliases` in both branches; add `visit_ImportFrom` for `os.system/popen*`.

**10. `subprocess(shell=True)` missed when `subprocess` is aliased or `run` is `from`-imported**
*HIGH (claimed CRITICAL) · `_is_subprocess_shell_true:1063*`
Repro: `import subprocess as sp; sp.run(cmd, shell=True)` → `total:0`; `from subprocess import run; run(cmd, shell=True)` → `total:0`; pickle-alias control fires.
Root cause: `_is_subprocess_shell_true` hard-codes `node.func.value.id == "subprocess"` while sibling `_is_pickle_load`/`_is_unsafe_yaml_load` consult `_module_aliases.get(...)`. The engine **inconsistently honors the very alias map it populates**. From-import additionally fails the Attribute guard. Engine's own SUBPROCESS_SHELL severity is HIGH.
Fix: Replace the literal with `self._module_aliases.get(node.func.value.id, node.func.value.id) == "subprocess"`; add `visit_ImportFrom`.

**11. `pickle.load/loads` missed for `from pickle import loads`**
*HIGH · `_is_pickle_load:1198`*
Repro: `from pickle import loads; loads(data)` → `total:0`; `import pickle as p; p.loads(data)` fires CRITICAL. Also `from pickle import loads as pl; pl(...)` and `from yaml import load` miss.
Root cause: `_is_pickle_load` requires `isinstance(node.func, ast.Attribute) and node.func.attr in {load,loads} and isinstance(node.func.value, ast.Name)` — a module.attr shape. The from-import yields a bare Name. Bug, not gap: shipped `test_pickle_alias_detected`/`test_cpickle_alias_detected` and the `_module_aliases` docstring advertise alias detection, but the more common from-import form silently misses with zero test coverage. Missed finding is the engine's own CRITICAL tier (CWE-502 RCE).
Fix: Add `visit_ImportFrom` mapping `from pickle/cPickle/_pickle import load/loads`; accept bare-Name calls of tracked names in `_is_pickle_load`.

**12. `yaml.load` missed for `from yaml import load`**
*HIGH · `_is_unsafe_yaml_load:1207`*
Repro: `from yaml import load; load(data)` → `total:0`; `import yaml as y; y.load(data)` fires HIGH/CWE-502. Also `from yaml import unsafe_load`, `from yaml import load as L` miss.
Root cause: Same module.attr-shape guard. **Asymmetry:** `_is_safe_loader_expr:1529` *does* resolve a bare-name `SafeLoader` after `from yaml import SafeLoader` — so the engine can **exonerate** a from-imported loader but never **flag** a from-imported sink (clear-only, never catch). Documented-capability bypass.
Fix: `visit_ImportFrom` for `from yaml import load/unsafe_load/unsafe_load_all/load_all`; accept bare-Name calls in `_is_unsafe_yaml_load`.

**13. Bare-name deserialization (`from pickle import loads; loads(x)`) not flagged**
*HIGH (claimed MEDIUM) · `_is_pickle_load:1198`*
Same defect family as #11, broadened: `from yaml import load; load(request.data)` and `from pickle import loads as pl; pl(...)` all emit `0`. Engine added `_module_aliases` (implying import-shape robustness) but never added `visit_ImportFrom`, so the entire from-imported dangerous-symbol family is invisible. Severity HIGH (missed finding is CRITICAL RCE in its most common import shape).

**14. Any `.open()` attribute call flagged as path traversal (`webbrowser.open`, `driver.open`)**
*HIGH (claimed MEDIUM) · `_path_traversal_sink_name:1455`*
Repro: `webbrowser.open(url)` / `browser.open(target)` / `driver.open(request.args.get('u'))` all emit SEC-PY_PATH_TRAVERSAL (CWE-22, HIGH, reachable:true) — **and the taint_chain `expr` is rewritten to a fabricated literal `open(url)`** (from `ast_analyzer.py:947` `f"{sink_name}({...})"`). Constant args correctly suppressed.
Root cause: `_path_traversal_sink_name` returns the leaf attr for **any** `ast.Attribute` whose attr ∈ `_PATH_TRAVERSAL_SINK_NAMES` (`{open,Path,send_file,send_from_directory}`) with no receiver allow-list. `open` is the most collision-prone method name in Python (selenium/playwright, zipfile/tarfile members, urllib OpenerDirector, sockets, dbm/shelve, ORM sessions). Wrong CWE + reachable-escalated + fabricated evidence = HIGH.
Fix: For the bare `open` sink, match only `ast.Name open(...)` (builtin) or an explicit filesystem-receiver allow-list (`io/os/codecs/gzip/bz2/lzma`); same scoping for `Path` (only `pathlib.Path`/bare `Path`).

**15. `cursor.execute()` flags CRITICAL on constant/literal-only SQL (no const-fold)**
*HIGH · `_is_sql_injection:1079`*
Repro: `table="users"; cursor.execute(f"SELECT * FROM {table} WHERE active=1")`, `cursor.execute("SELECT 1 " + "FROM t")`, `cursor.execute("SELECT * FROM {}".format("users"))` all flag CRITICAL/HIGH-confidence. Even an f-string with **zero** interpolations flags (parser yields `ast.JoinedStr` not `ast.Constant`).
Root cause: `_is_sql_injection` returns True for any `BinOp`/`JoinedStr`/`Call` first arg (and Names resolving to those) with **no constant-folding and no `_arg_is_sanitised` call**. Every other sink (SSRF/open-redirect/path/XSS) routes through `_arg_is_sanitised:559` which folds const BinOps. Literal SQL assembly is near-universal → high-volume CRITICAL FP that fails CI gates and buries real findings.
Fix: Before returning True, run a const-fold: `JoinedStr` requires ≥1 non-constant FormattedValue; `BinOp` requires ≥1 recursively-non-constant operand; `Call` (`.format`) requires ≥1 non-constant arg. Reuse `_arg_is_sanitised` scope resolution.

**16. `open()`/`Path()`/`send_file()` flag HIGH on fully-constant paths wrapped in a Call or f-string**
*HIGH · `_is_path_traversal_sink` / `_arg_is_sanitised:559`*
Repro (directory scan): `open(os.path.join("/srv","x.txt"))`, `open(os.path.expanduser("~/.netrc"))`, `open(f"{__file__}/../data.txt")`, `BASE="/srv/data"; open(os.path.join(BASE,"static"))` all flag HIGH/CWE-22. `open("/a"+"/b")` (top-level BinOp) is correctly suppressed.
Root cause: `_arg_is_sanitised` const-folds a **top-level BinOp** but **not** a `Call` or `JoinedStr`. `open(os.path.join(c,c))` is a Call; `open(f"{__file__}/x")` is a JoinedStr — neither recognized, so the open-family "emit on any non-constant arg" posture fires. Ubiquitous safe idioms (config loaders, `__file__`-relative package data, fixtures); bandit/Semgrep don't flag them. *(The single-file CLI repro in the original claim is non-reproducible — bug only manifests on directory scans, which is production behavior.)*
Fix: Const-fold `ast.JoinedStr` (safe when every FormattedValue is constant / Name→Constant / known dunder like `__file__`) and recognize `os.path.join/expanduser/expandvars/abspath/dirname/normpath` calls over all-safe args as safe, inside `_arg_is_sanitised`.

**17. Outer-scope same-name constant falsely suppresses an inner tainted sink (shadowing not honored)**
*HIGH (claimed CRITICAL) · `_cmdi_arg_is_dangerous:1058-1060`, `_is_ssrf:1322-1324`, plus open-redirect/XSS/path loops (1280/1391/1447)*
Repro: module-level `name="default"` + function-local `name=request.args.get('cmd')` → `os.system(name)` → `total:0`. Same for SSRF with `url`. **`cursor.execute` correctly fires** (`_is_sql_injection:1099-1102` returns the isinstance result on the first matching scope). Removing only the outer constant flips both to HIGH.
Root cause: The suppression loops do `for scope in reversed(self._scopes): if name in scope and isinstance(scope[name], ast.Constant): return False` with **no `break`**. `reversed()` visits the inner function scope first (name=Call → condition false, but no break), then falls through to module scope (name=Constant) → returns "safe." Python is innermost-wins; this loop is outermost-can-veto. `_is_sql_injection` and lines 554/579/1186 use the correct first-match form — internal inconsistency confirms oversight. Class bodies make it worse (no `visit_ClassDef`, so `class C: name='safe'` leaks into module scope).
Fix: In every suppression loop, `break` at the first scope defining the name (mirror `_is_sql_injection`); add `visit_ClassDef` to push/pop a scope.

**18. RecursionError in the route-index pre-pass aborts the entire injection pass**
*HIGH · `ASTAnalyzer.run:99` → `_build_route_index` → `route_extractor.extract_routes` (catches only SyntaxError, `route_extractor.py:100-103`)*
Repro: a tree containing one deeply-nested expression (≥496-term `a+a+…` BinOp chain trips the default recursionlimit of 1000) plus a plain `os.system(request.args.get('c'))` → stdout `{"done":true,"total":0}`, stderr `check 'injection (ast)' failed: maximum recursion depth exceeded`. The clean file's obvious finding is silenced. Monkeypatching out `_build_route_index` makes the same tree succeed (per-file guard catches it; `total:2`).
Root cause: `run` calls `_build_route_index(root)` **before** the per-file loop; `extract_routes` catches only `SyntaxError`. The RecursionError escapes `run()`, is caught by `engine.py:_run_check`'s broad handler, and **abandons the whole injection check**. The careful per-file `RecursionError` guard in `_analyze_python` (185) is bypassed because route extraction runs outside it. One crafted or merely large generated file zeroes out all injection findings tree-wide — trivial DoS, also trippable by benign machine-generated code. *(Nested-list-literal fixture does NOT reproduce on 3.14 — hits "too many nested parentheses" SyntaxError first; the BinOp vector is the version-correct reproducer.)*
Fix: Wrap the per-file `extract_routes` loop in `_build_route_index` in `try/except (RecursionError, Exception)` (log + continue); broaden `extract_routes`'s `except SyntaxError` to also catch `RecursionError`. Route binding must be truly best-effort.

**19. `npm audit` error-document / exit-1 silently treated as a clean scan**
*HIGH · `deps.py:_run_npm_audit:486-550`*
Repro (unmocked): `package.json {lodash 4.17.20}` + a legacy `"lockfileVersion":1` lock makes real npm return `{"error":{"code":"ENOLOCK"…}}` + exit 1; engine emits `{"done":true,"total":0}` with **empty stderr**. The local fallback would have flagged lodash CVE-2021-23337.
Root cause: `_run_npm_audit` only bails on returncode ∉ {0,1} (line 508). For exit 1 it `json.loads` the error doc, does `data.get("vulnerabilities") or {}` → `{}` (533), iterates zero entries, returns True (550) — so `_check_npm` treats the primary path as successful and skips `_local_npm_check`. The sibling pip-audit path **has** this guard (348-361, documented as a known silent-zero regression); it was never ported to npm. Triggers on out-of-sync v1 locks, private-registry auth failures, offline audits — common in real repos. Logs nothing (pip-audit logs "falling back").
Fix: After the returncode check, if returncode==1 and (`"error" in data` or `"vulnerabilities" not in data`), log a stderr warning and `return False` so the fallback fires. *(A literal port of the pip-audit empty-stdout guard would NOT catch this — the npm error doc has non-empty stdout.)*

**20. `requirements.txt` entries with extras (`pkg[extra]==ver`) dropped entirely**
*HIGH · `deps.py:_REQ_LINE_RE:209-211` / `_parse_requirements:214-226`*
Repro (pip-audit hidden, local path): `requests[security]==2.19.0` → no finding; control `requests==2.19.0` → 4 findings incl. CVE-2018-18074/CVE-2023-32681.
Root cause: `_REQ_LINE_RE = ^\s*([A-Za-z0-9_.\-]+)\s*([><=!~^]{1,3}\s*[\d.]+.*?)?…` — the name group excludes `[`, and the optional version group must start with a comparator, so `[security]` makes the whole line fail to match; the pinned vulnerable version is silently lost. Extras are pervasive (`celery[redis]`, `uvicorn[standard]`, `django[argon2]`). **The shipped engine Docker image does not install pip-audit**, so `shutil.which('pip-audit')` is None in production — this regex list is the **default** SCA path for `requirements.txt`, not a rare offline corner.
Fix: `^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([><=!~^]{1,3}…)` keeping group(1) as the bare name.

### MEDIUM / LOW

**21. Recognized sources through plain-name assignment lose chain/reachable/route on os.system-family sinks**
*MEDIUM · `_collect_taint_chain:353`; sink emission 625-644/934-976.* Contract bug: cookies/headers/`get_json`/`FILES`/FastAPI-param → `os.system(c)` fire HIGH but drop `taint_chain`+`reachable`+`route` (the documented Proven Path v1 tier the Go correlator uses to escalate HIGH→CRITICAL). Fixing the source gaps (#3-6) restores them; no sink change needed.

**22. npm caret/tilde ranges flagged at their floor → FP on already-patched ranges**
*MEDIUM · `deps.py:_local_npm_check:565` (`re.sub(r"^[^0-9]*","")`).* `lodash:"^4.17.20"` → HIGH SEC-DEPS-CVE_2021_23337, but `^4.17.20` resolves to 4.17.21+ (patched). Floor is compared as installed. Only fires on the curated local path (4 CVEs). Fix: for non-exact specs (`^`/`~`/`>=`) downgrade to INFO/LOW, or read the lockfile.

**23. Weak-password-hash heuristic fires on substring matches (`secretary`, `password_field_label`)**
*MEDIUM · `_looks_like_password_id:1555-1561` / `_is_weak_password_hash`.* `hashlib.md5(secretary.encode())`, `md5(password_field_label.encode())`, `md5(secret_seed)` all flag HIGH/CWE-916; `keyboard`/`etag_seed` correctly don't. `_PASSWORD_SUBSTR_TOKENS` (`password,passwd,passphrase,secret`) are raw substring-matched (1558) with no word boundary; only `pw`/`pwd` get whole-token matching. Fix: whole-token-match the long tokens via `_TOKEN_SPLIT_RE`.

**24. `html.escape()`/markupsafe sanitizers before an XSS sink not recognized — contradicts the engine's own fix text**
*MEDIUM · `_is_xss_html_sink:1367-1397` / `_arg_is_sanitised:559`.* `name = html.escape(request.args.get("name")); Markup(name)` flags HIGH/reachable — yet the finding's own remediation says "html.escape() the value before marking it safe." `_arg_is_sanitised` only knows dict-whitelist and membership-guard sanitizers; it has no notion of escaping/encoding neutralizers (`html.escape`, `markupsafe.escape`, `bleach.clean`, `django.utils.html.escape`). Fix: add an escaping-sanitizer recognizer per sink class.

**25. Tuple-unpacking assignment target not tracked → chain-gated SQLi fully missed**
*MEDIUM · `visit_Assign:995-1006` (single-target Name only).* `q,_ = "…"+request.args['x']+"'", 1; cursor.execute(q)` → `total:0`; single-target control fires CRITICAL. `os.system` via tuple still fires but without chain. Fix: handle `ast.Tuple`/`ast.List` targets (zip element-wise; record whole-RHS for non-decomposable RHS). *(Docstring disclaims tuple targets but claims "without changing detection rate" — that claim is false.)*

**26. Attribute-assignment target (`self.q = tainted`) not tracked → SQLi via self attribute missed**
*MEDIUM · `visit_Assign` + `_is_sql_injection` Name-only resolution.* `self.q = "…"+request.args['x']+"'"; cursor.execute(self.q)` → `total:0`; local-var control fires CRITICAL. Two compounding gaps: visit_Assign ignores Attribute targets, and `_is_sql_injection` returns False for an `ast.Attribute` sink-arg. `os.system(self.cmd)` still fires (no chain). Common in class-based views/repository helpers.

**27. Dict/list element flow (`d['k']=tainted; sink(d['k'])`) not tracked → chain-gated SQLi missed**
*MEDIUM (claimed; verifier raised to HIGH) · `visit_Assign` (Subscript target ignored) + `_is_sql_injection` (Subscript arg unresolved).* `d['q'] = "…"+request.args['x']; cursor.execute(d['q'])` → `total:0`; Name-var control fires CRITICAL. `os.system(d['cmd'])` fires without chain. Inline params-dict and f-string-into-dict variants also miss.

**28. Walrus (`:=`) inside `cursor.execute` not unwrapped → SQLi missed (works for os.system)**
*MEDIUM · `_is_sql_injection:1086-1103` (no `ast.NamedExpr` handling).* `cursor.execute(q := "…"+request.args['x']+"'")` → `total:0`; `os.system(cmd := request.args['x'])` fires with chain. Sink-predicate inconsistency. Fix: `if isinstance(first_arg, ast.NamedExpr): first_arg = first_arg.value` at the top of each strict predicate, and unwrap in `_trace_to_source`.

**29. Aliased / module-qualified request object not recognized (`request as rq`, `flask.request`)**
*MEDIUM · `_REQUEST_NAMES:1632` + `_references_request_input:1601`.* `from flask import request as rq; rq.args.get("f")` → `total:0`; `flask.request.args.get(...)` → `total:0`; bare `request` fires. `_REQUEST_NAMES` is a literal `{"request","req"}`; no `visit_ImportFrom`, no module-qualified Attribute match. Less-common styles → low end of MEDIUM.

**30. Empty-object security requirement (`{}`) not recognized as anonymous access**
*MEDIUM (claimed HIGH) · `spec_parser.py:_check_per_endpoint_auth:229`, `_check_no_global_security:134`, line 209.* `security: [{}, bearerAuth]` and global `security: [{}]` → `total:0`; literal `security: []` controls fire OPEN-ENDPOINT / NO-GLOBAL-AUTH+NO-AUTH. `[{}] == []` is False; `bool([{}])` is True, so the truthiness checks treat a globally-anonymous API as secured. In OpenAPI 3.x `{}` is the sanctioned "auth optional" idiom. Fix: add an `_allows_anon(sec)` helper used in place of `== []`/truthiness everywhere.

**31. Scoped npm package IDs retain the `/` separator (`SEC-DEPS-NPM-BABEL/TRAVERSE`)**
*LOW · `deps.py:_run_npm_audit:538`.* `f"SEC-DEPS-NPM-{pkg_name.upper().replace('-','_').replace('@','')}"` strips `@` and maps `-→_` but never handles the scope `/`. Affects all scoped packages (`@types/node`, `@aws-sdk/client-s3`). Cosmetic — SARIF grouping keys off `ruleKeyFor()`, not the finding id, so no functional breakage. Fix: add `.replace('/','_')`.

**32. Explicit global `security: []` mislabeled "no top-level security applied" and double-reported**
*LOW · `spec_parser.py:134/209`.* `security: []` emits NO-GLOBAL-AUTH (evidence "no top-level 'security' applied" — factually wrong, a field IS present) **plus** a per-endpoint NO-AUTH; byte-identical output to a spec with no security key at all. The conclusion (auth disabled) is correct; the wording + duplication are the defect. Fix: branch on `global_security is None` vs `== []` with distinct evidence.

**33. Arbitrary-equality pins (`===X.Y`) not recognized as pins → downgraded to INFO**
*MEDIUM (claimed LOW) · `deps.py:_extract_pinned_version:229-232`.* `pyyaml===5.0` → two INFO "unpinned" advisories; `pyyaml==5.0` → two CRITICAL. `re.match(r'^==\s*([\d.]+)', spec)` doesn't consume the third `=`. PEP 440 `===` is an exact pin. Only on the local-fallback path. Fix: `r'^={2,3}\s*([\w.\-+!]+)'`.

**34. Pre-release pins (`9.0.1rc1`) parse equal to the final release → missed vuln**
*LOW · `deps.py:_parse_version:183-194`.* `pillow==9.0.1rc1` (vulnerable to CVE-2022-22817, safe_from 9.0.1) → `total:0`; `_parse_version('9.0.1rc1')==(9,0,1)==_parse_version('9.0.1')`, so `< 9.0.1` is False. Reproduces on the prod path too (pip-audit rejects the pre-release pin, falls back to the buggy local list). Narrow trigger (pre-release of the very fix version). Fix: use `packaging.version.Version`.

**35. PEP 440 epoch versions (`1!2.0`) misparsed — epoch swallowed**
*LOW · `deps.py:_parse_version:183-194`.* `_parse_version('1!2.0')==(1,0)`, so the engine computes `1!2.0 < 2.0` (inverted; epoch must dominate). `re.split(r'[.-]','1!2.0')→['1!2','0']`, leading-digit match keeps `1`. Curated DB has zero epoch safe_from values, so impact is a potential FP on epoch-bumped installs. Fix: `packaging.version.Version`.

---

## 3. Coverage Gaps (never claimed; roadmap FNs)

### Source gaps
- **FastAPI/Starlette typed params** (also a bug — see #2): the canonical way every FastAPI endpoint receives input. Path-traversal-via-param missed outright; cmdi/SSRF/`open` lose all route/reachability proof.
- **`os.environ` / `os.getenv` not a source** *(misclassified as a bug — see §6)*: `os.path.join("/data", os.environ["F"])` → `total:0`; `os.system(os.environ['CMD'])` fires without chain. **Documented scope boundary** (request-inputs only), consistent with CodeQL/Semgrep defaults. Leave unless the source model is intentionally expanded.

### Sink gaps
- **SSRF: httpx / aiohttp / urllib3** — `_ssrf_sink_name:1329` knows only `requests` + `urllib.request`. `httpx.get/post`, `aiohttp session.get/post`, `urllib3 pool.request("GET", url)` → `total:0`. httpx/aiohttp/urllib3 are the three dominant modern clients; CWE-918 (metadata/internal-network). **HIGH.** (urllib3's `request()` puts the URL in arg index 1.)
- **SSRF: `from urllib.request import urlopen`** — `urlopen(url)` (bare Name) misses; qualified `urllib.request.urlopen` fires. Dominant stdlib SSRF idiom. **HIGH** (verifier raised from MEDIUM).
- **`subprocess.getoutput`/`getstatusoutput`** — always shell-backed (verified via CPython `inspect`), never carry `shell=True`, so `_is_subprocess_shell_true:1063` never inspects them. Tainted call = CWE-78. **MEDIUM** (lower prevalence).
- **`asyncio.create_subprocess_shell` / `loop.subprocess_shell`** — no asyncio cmdi branch; the `_shell` suffix routes through `/bin/sh`. Idiomatic async-framework shell-out. **HIGH.**
- **`cursor.executemany` / `executescript`** — `_is_sql_injection` guards `attr == 'execute'` only. `executescript` enables **stacked-query** injection. **HIGH.** One-line fix: `attr in {'execute','executemany','executescript'}`.
- **`marshal.loads` / `dill.loads` / `jsonpickle.decode`** — `_is_pickle_load` allow-lists only `{pickle,cPickle,_pickle}`. dill is a pickle superset (RCE); jsonpickle.decode reconstructs arbitrary classes; marshal executes crafted code objects. **HIGH** (CWE-502).
- **`jinja2.Template(x).render()` / `env.from_string(x)`** — `_XSS_HTML_SINK_NAMES:1505` has `render_template_string` but not the lower-level constructor. Canonical SSTI → RCE. **HIGH** (verifier raised from MEDIUM).
- **`os.exec*` / `os.spawn*`** — only `os.system`+`os.popen*` handled. Tainted program path = arbitrary-program execution; `execvp`/`spawnvp` add PATH resolution. **MEDIUM** (no shell metachar expansion). `spawn*` program path is arg index 1.
- **Destructive filesystem sinks (`shutil.copy/copyfile/move`, `os.remove/unlink/rename/rmdir`)** *(misclassified as LOW → verifier raised to MEDIUM, §6)*: identical tainted var into `open(p)` fires HIGH+chain; into these → `total:0`. Arbitrary overwrite/delete (CWE-22 write/delete variant). **MEDIUM.**
- **`compile()` then non-eval/exec execution** *(misclassified, §6)*: standalone `compile(user_input)` is silent, but the dangerous `compile→exec`/`compile→eval` idiom is **already caught at the exec/eval sink with a full chain** (the taint walker traverses through `compile`). Residual miss is narrow (`types.FunctionType(code,...)()`). **LOW.**

### Propagation gaps
- **`for x in request.*` / `with … as x` targets** — no `visit_For`/`visit_With`, so the loop/with target is never bound. The sink still fires (HIGH) but **drops taint_chain+reachable**, costing the Go correlator's HIGH→CRITICAL `escalateNonCorrelatedReachable` (orchestrator.go:916-943, verified) plus SARIF proof. **LOW** (vuln still surfaced). Same class affects comprehension and walrus targets.
- Tuple/attribute/dict/walrus propagation — see bugs #25-28 (these are documented out-of-scope, hence GAP, but cause real chain-gated SQLi misses).

### SCA gaps
- **No lockfile-resolved SCA** — caret/tilde FP (#22) and the entire "declared range vs installed" problem stem from not reading `package-lock.json`/`poetry.lock`. The curated local list is a small static fallback (4 npm + ~13 PyPI CVEs).
- **PEP 440 / version comparison** — pre-release (#34), epoch (#35), `===` (#33), and the truncating tuple parser are all symptoms of a hand-rolled `_parse_version`. One `packaging.version.Version` swap fixes all four.

### Spec / route gaps
- **apiKey-in-query never flagged** — no `_check_apikey_in_query`. `type: apiKey, in: query` puts the secret in the URL (logs/proxy/history/Referer; CWE-598/OWASP API2/API8). Direct peer to the existing MEDIUM Basic-auth check. **MEDIUM.**
- **String-form server URLs** — `_check_http_scheme:179-182` filters non-dict entries via `isinstance(s, dict)`; `servers: ["http://x"]` (invalid but common shorthand) escapes the plaintext-scheme check. **LOW.**
- **APIRouter `prefix=` / Blueprint `url_prefix` not prepended** — `route_extractor._DecoratorRouteVisitor._handle` uses only `deco.args[0]`; the mounted pattern is incomplete in the Proven-Path display. Binding still succeeds (keyed on function name), severity unchanged. **LOW** (metadata only).
- **CBV `.as_view()`, `include()`, DRF `router.register`, Flask `add_url_rule`** — all extract zero routes (documented v1 scope: plain function views only). Route field is metadata only in the Python tier (routed vs unrouted SQLi both CRITICAL); loss is at the Go correlation tier. DRF ViewSets are the dominant API-first pattern. **LOW** (documented intentional gap; verifier downgraded from MEDIUM).
- **Cross-file handler-name collision** — `RouteTable.add:89` `by_func.setdefault(handler_func, route)` is a flat project-wide map; first-walked file wins. Two `def index` in different blueprints → b.py's finding mislabeled with a.py's route. Correct severity/file/line/chain; only the `route` label is wrong. **LOW.** Fix: key binding on `(file, func_name)`.

---

## 4. False Positives (confirmed noise)

| # | Safe pattern that wrongly flags | Finding emitted | Location |
|---|---|---|---|
| 14 | `webbrowser.open(url)`, `driver.open(x)`, any `obj.open(non-const)` | CWE-22 HIGH + **fabricated** `open(x)` chain | `_path_traversal_sink_name:1455` |
| 15 | `cursor.execute(f"…{const}…")`, `"a"+"b"`, `"…".format("lit")`, zero-interp f-string | SQLi **CRITICAL** | `_is_sql_injection:1079` |
| 16 | `open(os.path.join("/srv","x"))`, `open(f"{__file__}/x")`, `BASE="/srv"; open(os.path.join(BASE,"s"))` | CWE-22 HIGH | `_arg_is_sanitised:559` (no Call/JoinedStr fold) |
| 23 | `md5(secretary.encode())`, `md5(password_field_label.encode())` | CWE-916 HIGH | `_looks_like_password_id:1558` |
| 24 | `Markup(html.escape(x))`, `mark_safe(escape(x))`, `bleach.clean` | CWE-79 HIGH + reachable | `_is_xss_html_sink:1367` |
| — | `os.system("echo "+"hello")` (literal concat) *(LOW; verifier downgraded)* | CWE-78 HIGH | `_cmdi_arg_is_dangerous:1050` (no const-fold; also `_is_subprocess_shell_true` does no const check at all) |
| — | `int(request.args.get("id"))` → `requests.get("…/%d" % user_id)` *(LOW; documented narrow sanitizer scope)* | SSRF/open-redirect HIGH | `_arg_is_sanitised` (no coercion sanitizers) |
| 22 | `lodash:"^4.17.20"` (patched on install) | SEC-DEPS HIGH | `_local_npm_check:565` |
| 32 | global `security: []` | misleading evidence + duplicate finding | `spec_parser:134/209` |

**Membership-guard ordering/dominance** *(misclassified HIGH→MEDIUM, §6)*: `_name_is_membership_guarded:482` returns True if **any** `if X not in <literal>: return/raise/abort` exists anywhere in the function, ignoring ordering AND dominance — shared by SSRF/open-redirect/XSS/path. The guard-**after**-sink half is a documented accepted precision loss (docstring 493-497); the **non-dominating-branch** half (guard inside `if mode=="strict":`) is genuinely undocumented over-suppression. Narrow trigger. Fix: add a dominance/ordering check.

---

## 5. Robustness / Contract

- **`checks: null` crashes with no done-line** *(MEDIUM; verifier downgraded from HIGH)* — `engine.py:48` `request.get("checks", [])` returns `None` for explicit JSON null; line 67 `"secrets" in checks` raises `TypeError`, exit 1, **empty stdout** (violates the docstring's "always terminates with `{done:true,total:N}`"). The `and verbose` does NOT guard it (Python evaluates the `in` operand first). **Reachable from Go**: `ScanRequest.Checks []string` has no `omitempty` (spawner.go:25), so `json.Marshal(ScanRequest{})` emits `"checks":null`; on non-zero exit the whole whitebox scan aborts and all findings are lost. **Latent today** — the only production caller (orchestrator.go:882) always sets a non-nil slice — but any future/refactored/direct-stdin caller triggers it. Fix: `checks = request.get("checks") or []` + an outer `try/except` in `main()` that always prints a terminal done-line.
- **`checks: 5` (non-iterable scalar) — same crash** *(LOW; strict duplicate)* — `"secrets" in 5` → TypeError, empty stdout, exit 1. Unreachable from the typed Go caller (`[]string`); only direct-stdin. Same fix closes both.
- **Top-level JSON array/scalar (`[1,2,3]`, `"hello"`, `42`, `null`) crashes with no done-line** *(LOW; misclassified MEDIUM, §6)* — `json.loads` succeeds, bypassing the `JSONDecodeError` guard (43-46), then `request.get` at line 48 raises `AttributeError`. Unreachable from the typed Go struct (always marshals to an object). Minor: the malformed-JSON branch exits **2**, not 1; the AttributeError path exits 1. Fix: `if not isinstance(request, dict): …` routes into the existing done-line+error branch.
- **`os.walk` directory requirement** — not a defect but a sharp edge: a single-file `code_path` silently yields `total:0` (production always passes a repo root). Worth a guard/warning to prevent silent no-op scans.

---

## 6. Verified-Correct Behaviors (calibration anchors)

The audit found **no false alarms** — the REJECTED list is empty. The following were reproduced but are **correctly handled or correctly out-of-scope**, so the user should NOT worry about them:

- **The happy-path taint engine works**: `request.args`/`form`/`GET`/`json`(property)/`files`(lowercase) → `os.system`/`os.popen`/`cursor.execute`/`requests.get`/`open`/`Markup`/`render_template_string` all fire with full `taint_chain` + `reachable:true` + route binding.
- **Alias resolution exists and works for deserialization**: `import pickle as p; p.loads(...)`, `import yaml as y; y.load(...)`, `_pickle.loads(...)` all fire (the map is just never wired into the os/subprocess/SSRF branches — bugs #8-10).
- **Const-folding works for the right sinks**: `requests.get("a"+"b")`, `open("/a"+"/b")` (top-level BinOp), constant `os.system`/`open`/`webbrowser.open("https://…")` are correctly suppressed.
- **`_is_sql_injection` honors innermost-scope shadowing** (unlike its siblings — that's bug #17): the SQL sink fires on a shadowed inner tainted binding and correctly stays silent on a shadowed inner constant.
- **The taint walker propagates through `compile()`** (the claimed "compile breaks the chain" defect does **not** occur — §3): `compile→exec`/`compile→eval` is caught at the execution sink with a full chain.
- **`os.environ` exclusion is deliberate and standard** (not a bug): consistent with CodeQL/Semgrep defaults; env vars are operator-controlled.
- **Membership-guard-after-sink and `int()`-coercion-not-recognized are documented accepted precision tradeoffs** (only the non-dominating-branch sub-case is a genuine over-suppression).
- **Negative controls hold**: `keyboard`/`etag_seed`/`power` do NOT trip the password heuristic; constant `.open()` args, `^4.17.21`, exact pins, and spec-compliant dict-form servers behave correctly.
- **Per-file RecursionError guard works** when reached (the bug #18 is that route extraction runs *outside* it).

---

## 7. Accuracy-Enhancement Recommendations (ROI-ordered)

1. **`visit_ImportFrom` + alias-resolution in all sink predicates** *(addresses #8-13, SSRF-from-import gap, and the entire from-import sink family)* — the single highest-leverage change. `_module_aliases` is already populated by `visit_Import` but ignored by `_is_subprocess_shell_true`/`os.system`/`os.popen`/`_ssrf_sink_name`. Add one `visit_ImportFrom` recording `from {os,subprocess,pickle,yaml,requests,urllib.request} import …` and resolve receivers through the alias map. **Closes ~8 confirmed bugs/gaps, mostly RCE-class, in one coherent change.**

2. **`visit_AugAssign` + tuple/attribute/dict/walrus/for/with binding** *(#1, #25-28, for-loop gap)* — restores intra-function taint propagation through the common accumulator, container, and class-state idioms. `visit_AugAssign` alone fixes the report's #1 (CRITICAL-class total miss). Add `visit_For`/`visit_With`/`visit_ClassDef` to recover reachability proof and fix shadowing (#17).

3. **Swap `_parse_version` for `packaging.version.Version`** *(#33-35)* — one dependency, fixes pre-release ordering, epochs, `===`, and the truncating tuple parser simultaneously. Also broaden `_REQ_LINE_RE` for extras (#20).

4. **Lockfile-resolved SCA + npm error-doc guard** *(#19, #22)* — read `package-lock.json`/`poetry.lock` for the *installed* version (kills the caret/tilde FP), and port a content-aware (not empty-stdout) error-doc guard to `_run_npm_audit` so tool failures fall back instead of reporting clean. Ship pip-audit in the engine image so the regex fallback isn't the default path.

5. **A real sanitizer/neutralizer library** *(#24, membership-guard, int-coercion FP)* — give the taint walker a per-sink-class set of recognized neutralizers (`html.escape`/`markupsafe.escape`/`bleach.clean` for XSS; `int`/`float`/`uuid.UUID`/enum lookups for interpolation sinks) and a dominance check for membership guards. Directly cuts the highest-volume FP categories.

6. **Receiver allow-listing + universal const-fold** *(#14-16, cmdi-literal FP)* — scope the bare `open`/`Path` sink to builtin/filesystem receivers (kills the `webbrowser.open` wrong-CWE + fabricated-chain FP), and route **every** sink predicate through one `_arg_is_sanitised` that folds `BinOp` **and** `JoinedStr` **and** safe `os.path.*` Calls (kills literal-SQL and constant-path FPs). The SQL sink currently has no fold at all.

7. **Expand the source attr set + FastAPI param seeding** *(#2-6)* — add `cookies/COOKIES/headers/META/FILES`, the `get_json/get_data` method forms, and seed route-handler params. Restores `os.path.*` detection (#7) and the Proven-Path tier (#21) across mainstream framework patterns.

8. **Sink-family breadth** *(httpx/aiohttp/urllib3 SSRF; `executemany`/`executescript`; `getoutput`/`asyncio` cmdi; `marshal`/`dill`/`jsonpickle`; `jinja2.Template.render`; `os.exec*`/`spawn*`; destructive FS)* — each is a small membership-set extension over an already-working code path.

9. **Robustness hardening** *(#18, #30-32, contract crashes)* — best-effort the route-index pre-pass (`try/except RecursionError`), normalize the engine request shape so a terminal done-line is always emitted, and add the `_allows_anon`/`apiKey-in-query`/string-server spec checks.

10. **Labeled F1 benchmark + confidence calibration** — stand up a corpus of the fixtures in this report (and their controls) as a regression suite, then calibrate `confidence`/`reachable` against measured precision so the Go correlator's HIGH→CRITICAL escalation rests on validated signal rather than the current heuristic.

---

## 8. Suggested Fix Priority

| Issue | Effort | Accuracy impact | Priority |
|---|---|---|---|
| #1 `visit_AugAssign` (accumulator FN) | S | FN↓↓ (CRITICAL-class) | **P0** |
| #8-10 alias resolution in os/subprocess/SSRF sinks | S | FN↓↓ (RCE) | **P0** |
| #11-13 `visit_ImportFrom` for from-imported sinks | M | FN↓↓ (RCE/CWE-502) | **P0** |
| #18 best-effort route-index pre-pass (tree-wide abort/DoS) | S | FN↓↓ (all findings) | **P0** |
| #15 SQL const-fold (literal-SQL CRITICAL FP) | S | FP↓↓ | **P0** |
| #17 innermost-scope shadowing (`break` in 5 loops) | S | FN↓ (HIGH×5 families) | **P0** |
| #19 npm error-doc fallback guard (silent clean scan) | S | FN↓ (SCA) | **P1** |
| #20 requirements extras regex | S | FN↓ (SCA, default path) | **P1** |
| #14 `.open()` receiver allow-list (wrong-CWE + fake chain) | S | FP↓↓ | **P1** |
| #16 const-fold Call/JoinedStr in `_arg_is_sanitised` | M | FP↓↓ | **P1** |
| #24 escaping-sanitizer recognizer (XSS) | M | FP↓ | **P1** |
| #2-6 source attr set + FastAPI param seeding | M | FN↓↓ | **P1** |
| #7,#21 (auto-closed by #2-6) | — | FN↓ + proof restored | **P1** |
| SSRF httpx/aiohttp/urllib3 + urlopen from-import | S | FN↓ (CWE-918) | **P1** |
| SQLi `executemany`/`executescript` | S | FN↓ (stacked-query) | **P1** |
| cmdi `getoutput`/`asyncio`; deser `marshal`/`dill`/`jsonpickle`; SSTI `Template.render` | S–M | FN↓ (RCE) | **P1** |
| `packaging.version.Version` swap (#33-35) | S | FN↓ + FP↓ (SCA) | **P1** |
| #25-28 tuple/attr/dict/walrus propagation | M | FN↓ | **P2** |
| for/with target binding (reachability proof) | S | proof/escalation | **P2** |
| #22 caret/tilde range FP (lockfile read) | M | FP↓ (SCA) | **P2** |
| #23 password whole-token match | S | FP↓ | **P2** |
| membership-guard dominance check | M | FP↓ | **P2** |
| #30,#32 spec `{}`/`[]` auth semantics; apiKey-in-query; string servers | M | FN↓ + FP↓ (spec) | **P2** |
| #29 aliased/module-qualified request object | S | FN↓ | **P2** |
| `os.exec*`/`spawn*`; destructive FS sinks | S | FN↓ | **P2** |
| contract crashes (`checks:null`/scalar; non-object request) + done-line guarantee | S | robustness | **P2** |
| route metadata (#31 id slash, prefix, cross-file collision, CBV/DRF binding) | S–L | metadata accuracy | **P2** |

**Net posture:** the four P0 source/propagation/alias changes plus the route-index guard are all **S/M effort** and collectively eliminate the most damaging false negatives (silent RCE/SQLi misses) and the highest-volume false positive (literal-SQL CRITICAL). They should land first; the breadth additions (P1/P2) are mechanical set-extensions over already-correct code paths.

---

**Key source locations cited (all verified in `/Users/asaied/WorkDir/Fendix/fendix-engine/python`):** `ast_analyzer.py` — `_REQUEST_INPUT_ATTRS:1577`, `_REQUEST_NAMES:1632`, `os.path.*` gate `:959`, `_name_is_membership_guarded:482`, `visit_Assign:995`, `_cmdi_arg_is_dangerous:1033`, `_is_subprocess_shell_true:1063`, `_is_sql_injection:1079`, `_is_pickle_load:1198`, `_is_unsafe_yaml_load:1207`, `_is_ssrf:1293`, `_ssrf_sink_name:1329`, `_path_traversal_sink_name:1455`, `_looks_like_password_id:1555` (no `visit_AugAssign`/`visit_For`/`visit_With`/`visit_ImportFrom`/`visit_ClassDef` exist); `engine.py:48/67`; `deps.py:_parse_version:183`, `_REQ_LINE_RE:209`, `_extract_pinned_version:229`, `_run_npm_audit:486`, `_local_npm_check:565`; `spec_parser.py:134/179/209/229`; `route_extractor.py:89/100/158/211`.
