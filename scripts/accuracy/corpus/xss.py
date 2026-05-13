"""XSS-HTML-render accuracy corpus."""
from flask import Markup, render_template_string, request
from django.utils.safestring import mark_safe


def case_01_markup_request_arg():
    # EXPECT_TP: Markup() with user-controlled HTML
    user_html = request.args.get("html")
    return Markup(user_html)


def case_02_mark_safe_request_arg():
    # EXPECT_TP: Django mark_safe with user-controlled HTML
    user_html = request.GET["html"]
    return mark_safe(user_html)


def case_03_render_template_string_request_arg():
    # EXPECT_TP: SSTI via render_template_string
    template = request.args["tpl"]
    return render_template_string(template)


def case_04_multi_hop():
    # EXPECT_TP: assignment-hop before Markup sink
    raw = request.args["x"]
    block = "<div>" + raw + "</div>"
    return Markup(block)


def case_05_constant_safe():
    # EXPECT_TN: literal HTML — developer marking known-safe block
    return Markup("<b>static content</b>")


def case_06_name_from_scope_safe():
    # EXPECT_TN: variable resolves to a constant in scope
    html = "<div>known-safe</div>"
    return Markup(html)
