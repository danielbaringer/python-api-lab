# python-api-lab
Python Flask REST API for ServiceNow integration testing with OAuth 2.0, JWT Bearer, API Key, and Swagger UI documentation.

## 📖 Interactive Documentation (Swagger)

Once the application is running, access the interative API documentation at:

- **Swagger UI:** `http://localhost:8000/apidocs/` (or `https://your-domain.onrender.com/apidocs/`)
- **OpenAPI Specification:** `http://localhost:8000/apispec.json`

### 🔑 Authenticating in Swagger UI

1. **API Key Authentication:**
   - Click the **Authorize** button at the top right.
   - Insert your API Key into the `ApiKeyAuth` field.
   - Click **Authorize**.

2. **JWT Bearer Token Authentication:**
   - First, execute `/oauth/token` or `/oauth/token/client-credentials` to generate a token.
   - Copy the value of `access_token`.
   - Click **Authorize** at the top right.
   - Enter `Bearer <your_access_token>` into the `Bearer` field.
   - Click **Authorize**.

## 🛠️ Environment Variables

Ensure the following environment variables are set in your execution environment or `.env` file:

- `OAUTH_CLIENT_ID`: Your OAuth Client ID.
- `OAUTH_CLIENT_SECRET`: Your OAuth Client Secret.
- `JWT_SECRET_KEY`: Secret key used for signing JWTs (must be at least 32 characters).
- `API_KEY`: Secret API Key for `x-api-key` header (must be at least 32 characters).
- `SWAGGER_HOST` *(optional)*: Override the base host for Swagger UI (defaults to `python-api-lab.onrender.com`).
