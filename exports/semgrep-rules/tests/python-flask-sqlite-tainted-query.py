"""Static Semgrep fixtures; never import or execute these examples."""

import sqlite3
import sqlite3 as sqlite

import flask
from flask import request


def connection_fstring():
    db = sqlite3.connect(":memory:")
    user_id = request.args["id"]
    # ruleid: appsec-python-flask-sqlite-tainted-query
    db.execute(f"SELECT * FROM users WHERE id = '{user_id}'")


def cursor_format():
    db = sqlite3.connect(":memory:")
    cursor = db.cursor()
    name = request.form.get("name")
    # Preserve the format-call syntax as a detection regression case.
    query = "SELECT * FROM users WHERE name = '{}'".format(name)  # noqa: UP032
    # ruleid: appsec-python-flask-sqlite-tainted-query
    cursor.execute(query)


def connection_percent():
    db = sqlite3.connect(":memory:")
    name = flask.request.form["name"]
    # ruleid: appsec-python-flask-sqlite-tainted-query
    db.execute("SELECT * FROM users WHERE name = '%s'" % name)  # noqa: UP031


def context_manager_and_alias():
    with sqlite.connect(":memory:") as db:
        query = request.args.get("query")
        # ruleid: appsec-python-flask-sqlite-tainted-query
        db.executescript(query)


def cursor_in_context():
    with sqlite3.connect(":memory:") as db:
        cursor = db.cursor()
        name = request.args.get("name")
        query = "INSERT INTO users (name) VALUES ('" + name + "')"
        # ruleid: appsec-python-flask-sqlite-tainted-query
        cursor.executemany(query, [(), ()])


def bound_parameters():
    db = sqlite3.connect(":memory:")
    user_id = request.args["id"]
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    cursor = db.cursor()
    # ok: appsec-python-flask-sqlite-tainted-query
    cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
    # ok: appsec-python-flask-sqlite-tainted-query
    cursor.executemany("INSERT INTO users (id) VALUES (?)", [(user_id,)])


def static_query():
    db = sqlite3.connect(":memory:")
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute("SELECT * FROM users")


def overwritten_query():
    db = sqlite3.connect(":memory:")
    query = request.args["query"]
    query = "SELECT * FROM users"
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute(query)


def unrelated_receiver(service):
    # ok: appsec-python-flask-sqlite-tainted-query
    service.execute(request.args["command"])


def non_flask_input():
    db = sqlite3.connect(":memory:")
    values = {"id": "1"}
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute("SELECT * FROM users WHERE id = " + values.get("id"))


def remaining_sql_methods():
    db = sqlite3.connect(":memory:")
    query = request.form["query"]
    # ruleid: appsec-python-flask-sqlite-tainted-query
    db.executemany(query, [(), ()])
    cursor = db.cursor()
    # ruleid: appsec-python-flask-sqlite-tainted-query
    cursor.executescript(query)


def parameter_binding_does_not_fix_interpolated_sql():
    db = sqlite3.connect(":memory:")
    column = request.args["column"]
    # ruleid: appsec-python-flask-sqlite-tainted-query
    db.execute(f"SELECT {column} FROM users WHERE id = ?", (1,))


def unsupported_source_is_a_known_gap():
    # JSON sources are deliberately outside this small initial subset.
    db = sqlite3.connect(":memory:")
    query = request.get_json()["query"]
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute(query)


def injected_connection_is_a_known_gap(db):
    # No locally established sqlite3 receiver, so this is not a covered sink.
    query = request.args["query"]
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute(query)


def shadowed_request_is_not_a_flask_source(request):
    db = sqlite3.connect(":memory:")
    # ok: appsec-python-flask-sqlite-tainted-query
    db.execute(request.args["query"])
