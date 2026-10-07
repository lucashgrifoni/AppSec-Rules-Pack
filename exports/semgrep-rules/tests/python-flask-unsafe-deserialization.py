# Intentionally vulnerable fixture for appsec-python-flask-unsafe-deserialization.
# Parsed by `semgrep --test`; never import or run it.
import marshal
import pickle
import pickle as serializer

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/state")
def restore_state():
    # ruleid: appsec-python-flask-unsafe-deserialization
    return pickle.loads(request.data)


@app.post("/state-alias")
def restore_state_alias():
    payload = request.get_data()
    # ruleid: appsec-python-flask-unsafe-deserialization
    return serializer.loads(payload)


@app.post("/upload")
def restore_upload():
    # ruleid: appsec-python-flask-unsafe-deserialization
    return pickle.load(request.files["state"])


@app.post("/code")
def load_code():
    # ruleid: appsec-python-flask-unsafe-deserialization
    return marshal.loads(request.get_data())


@app.post("/config")
def load_config():
    text = request.form["config"]
    # ruleid: appsec-python-flask-unsafe-deserialization
    return yaml.load(text, Loader=yaml.Loader)


@app.post("/config-unsafe")
def load_config_unsafe():
    # ruleid: appsec-python-flask-unsafe-deserialization
    return yaml.unsafe_load(request.args.get("config"))


@app.post("/config-safe")
def load_config_safe():
    # ok: appsec-python-flask-unsafe-deserialization
    return yaml.safe_load(request.data)


@app.post("/config-safe-loader")
def load_config_safe_loader():
    # ok: appsec-python-flask-unsafe-deserialization
    return yaml.load(request.data, Loader=yaml.SafeLoader)


def load_local_cache():
    with open("cache.pkl", "rb") as handle:
        # ok: appsec-python-flask-unsafe-deserialization
        return pickle.load(handle)
