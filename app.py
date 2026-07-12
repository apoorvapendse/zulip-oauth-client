"""Minimal OAuth2 client that uses Zulip as the authorization server.

Authorization-code + PKCE against ENABLE_ZULIP_OAUTH endpoints:

  GET  {realm}/o/authorize/
  POST {realm}/o/token/
  GET  {realm}/api/v1/users/me   (Authorization: Bearer …)

Register the app at {realm}/o/applications/ while logged into Zulip.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Any
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, render_template_string, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

ZULIP_REALM_URL = os.environ.get("ZULIP_REALM_URL", "http://zulip.zulipdev.com:9991").rstrip(
    "/"
)
CLIENT_ID = os.environ.get("ZULIP_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("ZULIP_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://127.0.0.1:5050/callback")
SCOPE = "api"

AUTHORIZE_URL = f"{ZULIP_REALM_URL}/o/authorize/"
TOKEN_URL = f"{ZULIP_REALM_URL}/o/token/"
USERS_ME_URL = f"{ZULIP_REALM_URL}/api/v1/users/me"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _new_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Zulip OAuth client showcase</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { max-width: 42rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
    pre { background: #1112; padding: 0.75rem 1rem; overflow: auto; border-radius: 6px; }
    .card { border: 1px solid #8884; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
    .err { border-color: #c33; background: #c331; }
    a.btn, button {
      display: inline-block; margin: 0.25rem 0.5rem 0.25rem 0;
      padding: 0.5rem 0.9rem; border-radius: 6px; border: 1px solid #8886;
      background: #246; color: #fff; text-decoration: none; cursor: pointer;
    }
    a.btn.secondary { background: transparent; color: inherit; }
    dt { font-weight: 600; margin-top: 0.5rem; }
    dd { margin: 0.15rem 0 0.5rem 0; }
  </style>
</head>
<body>
  <h1>Zulip OAuth client</h1>
  <p>
    Showcase for
    <a href="https://github.com/zulip/zulip/pull/38610">Zulip as an OAuth2 provider</a>
    (authorization code + PKCE, scope <code>api</code>).
  </p>

  {% if error %}
  <div class="card err"><strong>Error:</strong> {{ error }}</div>
  {% endif %}

  {% if not configured %}
  <div class="card err">
    <p>Missing <code>ZULIP_CLIENT_ID</code> / <code>ZULIP_CLIENT_SECRET</code>.</p>
    <ol>
      <li>Copy <code>.env.example</code> → <code>.env</code>.</li>
      <li>In Zulip, open <code>{{ realm }}/o/applications/</code> and register an app
          (grant type: authorization code).</li>
      <li>Set redirect URI to <code>{{ redirect_uri }}</code>.</li>
      <li>Paste client id/secret into <code>.env</code> and restart this app.</li>
    </ol>
  </div>
  {% elif profile %}
  <div class="card">
    <h2>Signed in</h2>
    <dl>
      <dt>Full name</dt><dd>{{ profile.full_name }}</dd>
      <dt>Email</dt><dd>{{ profile.email }}</dd>
      <dt>User id</dt><dd>{{ profile.user_id }}</dd>
      <dt>Realm</dt><dd>{{ profile.realm_name }} ({{ profile.realm_uri }})</dd>
    </dl>
    <p><a class="btn secondary" href="{{ url_for('logout') }}">Log out</a></p>
  </div>
  <div class="card">
    <h3><code>GET /api/v1/users/me</code></h3>
    <pre>{{ profile_json }}</pre>
  </div>
  {% else %}
  <div class="card">
    <p>Realm: <code>{{ realm }}</code></p>
    <p>Redirect URI: <code>{{ redirect_uri }}</code></p>
    <p><a class="btn" href="{{ url_for('login') }}">Log in with Zulip</a></p>
  </div>
  {% endif %}
</body>
</html>
"""


def _configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET)


@app.get("/")
def index() -> str:
    profile = session.get("profile")
    return render_template_string(
        PAGE,
        configured=_configured(),
        realm=ZULIP_REALM_URL,
        redirect_uri=REDIRECT_URI,
        profile=profile,
        profile_json=session.get("profile_json"),
        error=request.args.get("error"),
    )


@app.get("/login")
def login() -> Any:
    if not _configured():
        return redirect(url_for("index", error="Client not configured"))

    state = secrets.token_urlsafe(24)
    verifier, challenge = _new_pkce_pair()
    session["oauth_state"] = state
    session["code_verifier"] = verifier

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")


@app.get("/callback")
def callback() -> Any:
    if request.args.get("error"):
        return redirect(
            url_for(
                "index",
                error=request.args.get("error_description") or request.args.get("error"),
            )
        )

    if request.args.get("state") != session.pop("oauth_state", None):
        return redirect(url_for("index", error="Invalid OAuth state"))

    code = request.args.get("code")
    verifier = session.pop("code_verifier", None)
    if not code or not verifier:
        return redirect(url_for("index", error="Missing authorization code"))

    token_resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
        },
        timeout=30,
    )
    if not token_resp.ok:
        return redirect(
            url_for(
                "index",
                error=f"Token exchange failed ({token_resp.status_code}): {token_resp.text[:300]}",
            )
        )

    token_payload = token_resp.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        return redirect(url_for("index", error="No access_token in token response"))

    me_resp = requests.get(
        USERS_ME_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    if not me_resp.ok:
        return redirect(
            url_for(
                "index",
                error=f"users/me failed ({me_resp.status_code}): {me_resp.text[:300]}",
            )
        )

    me = me_resp.json()
    session["access_token"] = access_token
    session["profile"] = {
        "full_name": me.get("full_name"),
        "email": me.get("email"),
        "user_id": me.get("user_id"),
        "realm_name": me.get("realm_name"),
        "realm_uri": me.get("realm_uri") or ZULIP_REALM_URL,
    }
    session["profile_json"] = me_resp.text
    return redirect(url_for("index"))


@app.get("/logout")
def logout() -> Any:
    session.clear()
    return redirect(url_for("index"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "realm": ZULIP_REALM_URL}


def main() -> None:
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5050"))
    print(f"Zulip realm: {ZULIP_REALM_URL}")
    print(f"Authorize:   {AUTHORIZE_URL}")
    print(f"Token:       {TOKEN_URL}")
    print(f"Callback:    {REDIRECT_URI}")
    print(f"Open:        http://{host}:{port}/")
    # threaded helps when Zulip and this app share a machine under load
    app.run(host=host, port=port, debug=True, threaded=True)


if __name__ == "__main__":
    main()
