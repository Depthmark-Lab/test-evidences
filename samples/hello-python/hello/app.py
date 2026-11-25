"""Hello World web service: GET /hello?name=... and GET /health."""
from flask import Flask, jsonify, request

app = Flask(__name__)


def greeting(name):
    return f"Hello, {name.strip() if name and name.strip() else 'world'}!"


@app.get("/hello")
def hello():
    return jsonify(message=greeting(request.args.get("name")))


@app.get("/health")
def health():
    return jsonify(status="ok")
