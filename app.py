# app.py
from flask import Flask, render_template, request, jsonify
from sec_headers_checker import run_check
import traceback

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/run", methods=["POST"])
def run():
    try:
        data = request.json or {}
        target = data.get("target", "").strip()
        if not target:
            return jsonify({"error": "Please provide a domain (example.com)"}), 400
        report = run_check(target)
        return jsonify({"ok": True, "report": report})
    except Exception as e:
        # return a helpful message (no technical exploit detail)
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500

if __name__ == "__main__":
    app.run(debug=True)
