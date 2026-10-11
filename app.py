import os
import hmac
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
from flask import Flask, jsonify, request
from flasgger import Swagger

# ============================================================
# CONFIGURACAO FLASK, OAUTH 2.0 E API KEY
# ============================================================

app = Flask(__name__)

ISSUER = "https://python-api-lab.onrender.com"
AUDIENCE = "python-api-lab"
TOKEN_TTL = 3600

CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "")
API_KEY = os.environ.get("API_KEY", "")

if not CLIENT_ID or not CLIENT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("Invalid OAuth configuration")

if len(API_KEY) < 32:
    raise RuntimeError("API_KEY must have at least 32 characters")

# Configuração do Swagger UI
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Python API Lab",
        "description": "API Lab para testes de integração com OAuth 2.0, JWT Bearer e API Key.",
        "version": "1.0.0"
    },
    "host": os.environ.get("SWAGGER_HOST", "python-api-lab.onrender.com"),
    "basePath": "/",
    "schemes": ["https", "http"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Informe no formato: Bearer <seu_token_jwt>"
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "name": "x-api-key",
            "in": "header",
            "description": "Sua chave de API de 32+ caracteres"
        }
    }
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)


# ============================================================
# FUNCAO COMPARTILHADA - GERAR ACCESS TOKEN JWT
# ============================================================

def generate_access_token():

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


# ============================================================
# HEALTH CHECK E HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():
    """
    Informações da Aplicação
    ---
    tags:
      - System
    responses:
      200:
        description: Retorna metadados da API e endpoints disponíveis.
    """
    return jsonify({
        "application": "Python API Lab",
        "status": "online",
        "documentation": "/apidocs/",
        "authentication": [
            "OAuth 2.0 Client Credentials",
            "JWT Bearer Token",
            "API Key"
        ],
        "token_endpoints": [
            "/oauth/token",
            "/oauth/token/client-credentials"
        ],
        "api_endpoints": [
            "/health",
            "/api/echo",
            "/api/secure/echo",
            "/api/apikey/echo"
        ]
    }), 200


@app.route("/health", methods=["GET"])
def health():
    """
    Health Check
    ---
    tags:
      - System
    responses:
      200:
        description: Status da aplicação.
    """
    return jsonify({
        "status": "ok"
    }), 200


# ============================================================
# OAUTH 2.0 - CLIENT CREDENTIALS VIA BASIC AUTH
# POST /oauth/token
# ============================================================

@app.route("/oauth/token", methods=["POST"])
def token_basic():
    """
    OAuth 2.0 Token (Basic Auth)
    ---
    tags:
      - OAuth 2.0
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: Authorization
        in: header
        required: true
        type: string
        description: Credenciais no formato Basic Base64(client_id:client_secret)
      - name: grant_type
        in: formData
        type: string
        required: true
        enum: [client_credentials]
    responses:
      200:
        description: Token gerado com sucesso.
      400:
        description: Requisição inválida ou grant_type não suportado.
      401:
        description: Credenciais de cliente inválidas.
    """
    if request.mimetype != "application/x-www-form-urlencoded":
        return jsonify({
            "error": "invalid_request",
            "error_description": "Use application/x-www-form-urlencoded"
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
        }), 401, {
            "WWW-Authenticate": "Basic"
        }

    supplied_id = auth.username or ""
    supplied_secret = auth.password or ""

    valid_id = hmac.compare_digest(supplied_id, CLIENT_ID)
    valid_secret = hmac.compare_digest(supplied_secret, CLIENT_SECRET)

    if not (valid_id and valid_secret):
        return jsonify({
            "error": "invalid_client"
        }), 401, {
            "WWW-Authenticate": "Basic"
        }

    return generate_access_token()


# ============================================================
# OAUTH 2.0 - CLIENT CREDENTIALS VIA BODY
# POST /oauth/token/client-credentials
# ============================================================

@app.route("/oauth/token/client-credentials", methods=["POST"])
def token_client_credentials():
    """
    OAuth 2.0 Token (Form Body)
    ---
    tags:
      - OAuth 2.0
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: grant_type
        in: formData
        type: string
        required: true
        enum: [client_credentials]
      - name: client_id
        in: formData
        type: string
        required: true
      - name: client_secret
        in: formData
        type: string
        required: true
    responses:
      200:
        description: Token gerado com sucesso.
      400:
        description: Requisição inválida.
      401:
        description: Credenciais de cliente inválidas.
    """
    if request.mimetype != "application/x-www-form-urlencoded":
        return jsonify({
            "error": "invalid_request",
            "error_description": "Use application/x-www-form-urlencoded"
        }), 400

    if request.headers.get("Authorization"):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Do not send Authorization header"
        }), 400

    grant_type = request.form.get("grant_type", "")
    client_id = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")

    if grant_type != "client_credentials":
        return jsonify({
            "error": "unsupported_grant_type"
        }), 400

    valid_id = hmac.compare_digest(client_id, CLIENT_ID)
    valid_secret = hmac.compare_digest(client_secret, CLIENT_SECRET)

    if not (valid_id and valid_secret):
        return jsonify({
            "error": "invalid_client"
        }), 401

    return generate_access_token()


# ============================================================
# DECORATOR - VALIDACAO DO BEARER TOKEN JWT
# ============================================================

def require_oauth(required_scope):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            authorization = request.headers.get("Authorization", "")
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
                        'Bearer error="insufficient_scope", '
                        f'scope="{required_scope}"'
                }

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================
# DECORATOR - VALIDACAO DE API KEY
# ============================================================

def require_api_key(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        supplied_key = request.headers.get("x-api-key", "")

        if not supplied_key:
            return jsonify({
                "status": "error",
                "error": "missing_api_key",
                "message": "Header x-api-key is required"
            }), 401

        if not hmac.compare_digest(supplied_key, API_KEY):
            return jsonify({
                "status": "error",
                "error": "invalid_api_key",
                "message": "Invalid API Key"
            }), 401

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# ENDPOINT PUBLICO - REST / JSON
# POST /api/echo
# ============================================================

@app.route("/api/echo", methods=["POST"])
def echo():
    """
    Echo Público
    ---
    tags:
      - Echo Endpoints
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          example:
            mensagem: "Teste Público"
    responses:
      200:
        description: Retorna os dados JSON recebidos.
      400:
        description: JSON inválido.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    return jsonify({
        "status": "success",
        "data": data
    }), 200


# ============================================================
# ENDPOINT PROTEGIDO - OAUTH 2.0 / JWT
# POST /api/secure/echo
# ============================================================

@app.route("/api/secure/echo", methods=["POST"])
@require_oauth("echo:write")
def secure_echo():
    """
    Echo Protegido (JWT Bearer)
    ---
    tags:
      - Echo Endpoints
    security:
      - Bearer: []
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          example:
            mensagem: "Teste JWT"
    responses:
      200:
        description: Retorna os dados processados com sucesso.
      401:
        description: Token JWT ausente ou inválido.
      403:
        description: Escopo insuficiente.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    return jsonify({
        "status": "success",
        "authenticated": True,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": data
    }), 200


# ============================================================
# ENDPOINT PROTEGIDO COM API KEY
# POST /api/apikey/echo
# ============================================================

@app.route("/api/apikey/echo", methods=["POST"])
@require_api_key
def api_key_echo():
    """
    Echo Protegido (API Key)
    ---
    tags:
      - Echo Endpoints
    security:
      - ApiKeyAuth: []
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          example:
            mensagem: "Teste API Key"
    responses:
      200:
        description: Retorna os dados processados com sucesso.
      401:
        description: API Key ausente ou inválida.
    """
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A JSON object is required"
        }), 400

    return jsonify({
        "status": "success",
        "authenticated": True,
        "authentication_method": "API_KEY",
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": data
    }), 200


# ============================================================
# INICIALIZACAO LOCAL
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False
    )
