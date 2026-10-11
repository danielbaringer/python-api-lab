
# OAuth 2.0 Client Credentials via Body
@app.route("/oauth/token/client-credentials", methods=["POST"])
def token_client_credentials():

    if request.mimetype != "application/x-www-form-urlencoded":
        return jsonify({
            "error": "invalid_request",
            "error_description": "Use application/x-www-form-urlencoded"
        }), 400

    # Impede combinar Basic Auth e credenciais no Body
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
    valid_secret = hmac.compare_digest(
        client_secret, CLIENT_SECRET
    )

    if not (valid_id and valid_secret):
        return jsonify({
            "error": "invalid_client"
        }), 401

    # Gera Access Token JWT
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
