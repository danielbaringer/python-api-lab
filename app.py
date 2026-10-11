
from flask import Flask, request, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "application": "Python API Lab",
        "status": "online",
        "framework": "Flask"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/api/echo", methods=["POST"])
def echo():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    return jsonify({
        "status": "success",
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": data
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
