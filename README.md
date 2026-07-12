# Zulip OAuth client (showcase)

Minimal third-party app that signs users in with **Zulip as an OAuth2
provider** ([zulip/zulip#38610](https://github.com/zulip/zulip/pull/38610) /
[#17042](https://github.com/zulip/zulip/issues/17042)).

Flow:

1. Authorization code + **PKCE** against `{realm}/o/authorize/`
2. Code exchange at `{realm}/o/token/`
3. Zulip REST call with `Authorization: Bearer <access_token>` → `/api/v1/users/me`

Tokens use the experimental `api` scope (same access model as the user’s API key).

## Prerequisites

- A Zulip server with `ENABLE_ZULIP_OAUTH = True` (default in the Zulip
  development environment on the OAuth-provider branch).
- Python 3.11+.

## Register an OAuth application in Zulip

1. Log into the realm you will use (e.g. `http://zulip.zulipdev.com:9991`).
2. Open **`/o/applications/`** → register an application.
3. Grant type is fixed to **Authorization code**.
4. Set **Redirect URIs** to:

   ```text
   http://127.0.0.1:5050/callback
   ```

5. Copy the **Client id** and **Client secret**.

## Run this client

```bash
cd ~/Documents/programming/zulip-oauth-client
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: ZULIP_REALM_URL, ZULIP_CLIENT_ID, ZULIP_CLIENT_SECRET

python app.py
```

Open [http://127.0.0.1:5050/](http://127.0.0.1:5050/) → **Log in with Zulip**.

### `.env` keys

| Variable | Meaning |
|----------|---------|
| `ZULIP_REALM_URL` | Realm origin, no trailing slash (must match the host you registered the app on) |
| `ZULIP_CLIENT_ID` | From `/o/applications/` |
| `ZULIP_CLIENT_SECRET` | From `/o/applications/` |
| `OAUTH_REDIRECT_URI` | Must match a registered redirect URI exactly |
| `FLASK_PORT` | Local port (default `5050`) |

## Dev networking notes

- Zulip’s Docker/Vagrant dev server often listens on **port 9991**.
- Prefer the realm hostname (`zulip.zulipdev.com`) when that is how you
  browse Zulip; subdomain checks apply to API calls.
- If the browser cannot resolve `*.zulipdev.com`, add a hosts entry or
  use whatever origin you already use for the web app—**keep the OAuth
  app, this client’s `ZULIP_REALM_URL`, and the browser on the same origin**.

## Project layout

```text
app.py           Flask app: /login → Zulip → /callback → /api/v1/users/me
requirements.txt flask, requests, python-dotenv
.env.example     configuration template
```

## Not production-ready

This is a **local demo** for the experimental provider: secrets in `.env`,
Flask debug server, session cookie storage for the access token, no refresh
token handling UI. Use it to exercise the Zulip endpoints, not as a template
for a production integration without hardening.
