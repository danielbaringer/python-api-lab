
import os
import hmac
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

ISSUER = "https://python-api-lab.onrender.com"
AUDIENCE = "python-api-lab"
TOKEN_TTL = 3600

CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]
JWT_SECRET = os.environ["JWT_SECRET_KEY"]

if not CLIENT_ID or not CLIENT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("Invalid OAuth configuration")


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "application": "Python API Lab",
        "status": "online",
        "authentication": "OAuth 2.0 Client Credentials"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# Emissao de Access Token
@app.route("/oauth/token", methods=["POST"])
def token():
    if request.mimetype != "application/x-www-form-urlencoded":
        return jsonify({
            "error": "invalid_request",
            "error_description": "Use form-urlencoded"
        }), 400

    grant_type = request.form.get("grant_type")
    auth = request.authorization

    if grant_type != "client_credentials":
        return jsonify({
            "error": "unsupported_grant_type"
        }), 400

    if not auth or auth.type.lower() != "basic":
        return jsonify({
            "error": "invalid_client"
        }), 401, {"WWW-Authenticate": "Basic"}

    supplied_id = auth.username or ""
    supplied_secret = auth.password or ""

    valid_id = hmac.compare_digest(supplied_id, CLIENT_ID)
    valid_secret = hmac.compare_digest(
        supplied_secret, CLIENT_SECRET
    )

    if not (valid_id and valid_secret):
        return jsonify({"error": "invalid_client"}), 401, {
            "WWW-Authenticate": "Basic"
        }

    now = datetime.now(timezone.utc)

    payload = {
        "iss": ISSUER,
        "sub": CLIENT_ID,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=TOKEN_TTL),
        "scope": "echo:write"
    }

    access_token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    response = jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": "echo:write"
    })

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response, 200


# Decorator que valida o Bearer Token
def require_oauth(required_scope):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            authorization = request.headers.get(
                "Authorization", ""
            )

            parts = authorization.split()

            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({
                    "error": "invalid_token",
                    "message": "Bearer token required"
                }), 401, {
                    "WWW-Authenticate": "Bearer"
                }

            try:
                payload = jwt.decode(
                    parts[1],
                    JWT_SECRET,
                    algorithms=["HS256"],
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    options={
                        "require": [
                            "exp", "iat", "nbf",
                            "iss", "sub", "aud"
                        ]
                    }
                )

                if payload.get("sub") != CLIENT_ID:
                    raise jwt.InvalidTokenError()

            except jwt.PyJWTError:
                return jsonify({
                    "error": "invalid_token"
                }), 401, {
                    "WWW-Authenticate": "Bearer"
                }

            scopes = payload.get("scope", "").split()

            if required_scope not in scopes:
                return jsonify({
                    "error": "insufficient_scope"
                }), 403, {
                    "WWW-Authenticate":
                        f'Bearer error="insufficient_scope", scope="{required_scope}"'
                }

            return function(*args, **kwargs)
        return wrapper
    return decorator


# Endpoint publico para testes
@app.route("/api/echo", methods=["POST"])
def echo():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    return jsonify({
        "status": "success",
        "data": data
    }), 200


# Endpoint protegido por OAuth
@app.route("/api/secure/echo", methods=["POST"])
@require_oauth("echo:write")
def secure_echo():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    return jsonify({
        "status": "success",
        "authenticated": True,
        "received_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "data": data
    }), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False
    )
