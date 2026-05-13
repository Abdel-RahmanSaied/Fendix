"""CWE-79: XSS via HTML sinks."""
from __future__ import annotations

from flask import request, render_template_string, Markup, Flask
from markupsafe import escape

app = Flask(__name__)


@app.route("/bad01")
def bad_01_markup():
    name = request.args.get("name", "")
    return Markup(f"<h1>Hello {name}</h1>")  # SINK


@app.route("/bad02")
def bad_02_render_template_string():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")  # SINK


@app.route("/bad03")
def bad_03_multi_hop():
    raw = request.args.get("name", "")
    intermediate = raw
    return Markup(intermediate)  # SINK


@app.route("/bad04")
def bad_04_mark_safe():
    from django.utils.safestring import mark_safe
    name = request.args.get("name", "")
    return mark_safe(f"<p>{name}</p>")  # SINK


@app.route("/good01")
def good_01_escape():
    name = request.args.get("name", "")
    return f"<h1>Hello {escape(name)}</h1>"  # SAFE


@app.route("/good02")
def good_02_constant():
    return Markup("<h1>Hello world</h1>")  # SAFE — no taint
