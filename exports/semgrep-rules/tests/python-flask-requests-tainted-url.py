"""Static Semgrep fixtures; never import or execute these examples."""

import flask
import requests
import requests as http
from flask import request
from requests import get as fetch


def direct_get():
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.get(request.args["url"], timeout=5)


def assigned_url():
    target = request.form.get("target")
    url = target
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.post(url, timeout=5)


def keyword_url_with_alias():
    target = flask.request.args.get("target")
    # ruleid: appsec-python-flask-requests-tainted-url
    http.put(url=target, timeout=5)


def function_alias():
    # ruleid: appsec-python-flask-requests-tainted-url
    fetch(request.form["url"], timeout=5)


def generic_request():
    target = request.args["url"]
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.request("GET", target, timeout=5)
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.request("HEAD", url=target, timeout=5)
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.request(url=target, method="OPTIONS", timeout=5)


def other_methods():
    target = request.args.get("target")
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.patch(target, timeout=5)
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.delete(target, timeout=5)
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.head(target, timeout=5)
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.options(target, timeout=5)


def fixed_destination():
    # ok: appsec-python-flask-requests-tainted-url
    requests.get("https://api.example.test/status", timeout=5)


def payload_is_not_destination():
    value = request.args["query"]
    # ok: appsec-python-flask-requests-tainted-url
    requests.get("https://api.example.test/search", params={"q": value}, timeout=5)
    # ok: appsec-python-flask-requests-tainted-url
    requests.post(url="https://api.example.test/items", json={"name": value}, timeout=5)
    # ok: appsec-python-flask-requests-tainted-url
    requests.request("GET", "https://api.example.test/search", params={"q": value}, timeout=5)


def overwritten_url():
    target = request.args["url"]
    target = "https://api.example.test/status"
    # ok: appsec-python-flask-requests-tainted-url
    requests.get(target, timeout=5)


def unrelated_client(client):
    # ok: appsec-python-flask-requests-tainted-url
    client.get(request.args["key"])


def non_flask_input():
    values = {"url": "https://api.example.test/status"}
    # ok: appsec-python-flask-requests-tainted-url
    requests.get(values.get("url"), timeout=5)


def redirects_disabled_still_accepts_arbitrary_destination():
    target = request.args["url"]
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.get(target, allow_redirects=False, timeout=5)


def path_only_input_is_a_known_false_positive():
    # Conservative taint cannot distinguish the URL authority from a path suffix.
    item = request.args["id"]
    # ruleid: appsec-python-flask-requests-tainted-url
    requests.get("https://api.example.test/items/" + item, timeout=5, allow_redirects=False)


def unsupported_source_is_a_known_gap():
    # JSON sources are deliberately outside this small initial subset.
    target = request.get_json()["url"]
    # ok: appsec-python-flask-requests-tainted-url
    requests.get(target, timeout=5)


def session_is_a_known_gap():
    # Session instances are deliberately outside the covered module-level API.
    session = requests.Session()
    # ok: appsec-python-flask-requests-tainted-url
    session.get(request.args["url"], timeout=5)


def shadowed_request_is_not_a_flask_source(request):
    # ok: appsec-python-flask-requests-tainted-url
    requests.get(request.args["url"], timeout=5)
