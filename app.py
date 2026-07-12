"""Minimal OAuth2 client that uses Zulip as the authorization server.

Authorization-code + PKCE against ENABLE_ZULIP_OAUTH endpoints:

  GET  {realm}/o/authorize/
  POST {realm}/o/token/
  GET  {realm}/api/v1/users/me
  GET  {realm}/api/v1/users/{id}/status
  POST {realm}/api/v1/users/me/status

Tokens (access + refresh when issued) are kept in the Flask session and
mirrored to .token_cache.json so they survive a process restart.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, render_template_string, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

ZULIP_REALM_URL = os.environ.get("ZULIP_REALM_URL", "http://localhost:9991").rstrip("/")
CLIENT_ID = os.environ.get("ZULIP_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("ZULIP_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://127.0.0.1:5050/callback")
SCOPE = "api"
TOKEN_CACHE_PATH = Path(__file__).resolve().parent / ".token_cache.json"

# Status text/emoji flipped by the showcase toggle button.
SHOWCASE_STATUS_TEXT = "via OAuth client"
SHOWCASE_EMOJI_NAME = "zulip"
SHOWCASE_EMOJI_CODE = "zulip"
SHOWCASE_REACTION_TYPE = "zulip_extra_emoji"

AUTHORIZE_URL = f"{ZULIP_REALM_URL}/o/authorize/"
TOKEN_URL = f"{ZULIP_REALM_URL}/o/token/"
USERS_ME_URL = f"{ZULIP_REALM_URL}/api/v1/users/me"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _new_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET)


def _auth_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def _write_token_cache(tokens: dict[str, Any]) -> None:
    TOKEN_CACHE_PATH.write_text(json.dumps(tokens, indent=2) + "\n", encoding="utf-8")


def _read_token_cache() -> dict[str, Any] | None:
    if not TOKEN_CACHE_PATH.is_file():
        return None
    try:
        data = json.loads(TOKEN_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _clear_token_cache() -> None:
    try:
        TOKEN_CACHE_PATH.unlink(missing_ok=True)
    except OSError:
        pass


def _store_tokens(token_payload: dict[str, Any]) -> dict[str, Any]:
    """Persist full token response in session + on-disk cache."""
    now = int(time.time())
    expires_in = token_payload.get("expires_in")
    tokens: dict[str, Any] = {
        "access_token": token_payload.get("access_token"),
        "refresh_token": token_payload.get("refresh_token"),
        "token_type": token_payload.get("token_type", "Bearer"),
        "scope": token_payload.get("scope"),
        "expires_in": expires_in,
        "obtained_at": now,
        "expires_at": (now + int(expires_in)) if expires_in is not None else None,
        "raw": token_payload,
    }
    session["tokens"] = tokens
    session["access_token"] = tokens["access_token"]
    if tokens.get("refresh_token"):
        session["refresh_token"] = tokens["refresh_token"]
    else:
        session.pop("refresh_token", None)
    _write_token_cache(tokens)
    return tokens


def _load_tokens() -> dict[str, Any] | None:
    tokens = session.get("tokens")
    if isinstance(tokens, dict) and tokens.get("access_token"):
        return tokens
    cached = _read_token_cache()
    if cached and cached.get("access_token"):
        session["tokens"] = cached
        session["access_token"] = cached["access_token"]
        if cached.get("refresh_token"):
            session["refresh_token"] = cached["refresh_token"]
        return cached
    return None


def _fetch_users_me(access_token: str) -> requests.Response:
    return requests.get(
        USERS_ME_URL,
        headers=_auth_headers(access_token),
        timeout=30,
    )


def _status_url(user_id: int) -> str:
    return f"{ZULIP_REALM_URL}/api/v1/users/{user_id}/status"


def _update_status_url() -> str:
    return f"{ZULIP_REALM_URL}/api/v1/users/me/status"


def _fetch_user_status(access_token: str, user_id: int) -> requests.Response:
    return requests.get(
        _status_url(user_id),
        headers=_auth_headers(access_token),
        timeout=30,
    )


def _set_user_status(access_token: str, payload: dict[str, Any]) -> requests.Response:
    # Zulip typed_endpoint accepts form-encoded fields for this route.
    return requests.post(
        _update_status_url(),
        headers=_auth_headers(access_token),
        data=payload,
        timeout=30,
    )


def _status_from_get_response(resp: requests.Response) -> dict[str, Any]:
    if not resp.ok:
        return {}
    body = resp.json()
    # Response shape: {"status": {"status_text": "...", "emoji_name": "...", ...}}
    status = body.get("status")
    return status if isinstance(status, dict) else {}


def _record_api_call(method: str, url: str, resp: requests.Response) -> None:
    session["last_api_call"] = {
        "method": method,
        "url": url,
        "status_code": resp.status_code,
        "body": resp.text,
    }


def _hydrate_profile(access_token: str) -> dict[str, Any] | None:
    me_resp = _fetch_users_me(access_token)
    _record_api_call("GET", USERS_ME_URL, me_resp)
    if not me_resp.ok:
        return None
    me = me_resp.json()
    profile = {
        "full_name": me.get("full_name"),
        "email": me.get("email"),
        "user_id": me.get("user_id"),
        "realm_name": me.get("realm_name"),
        "realm_uri": me.get("realm_uri") or ZULIP_REALM_URL,
    }
    session["profile"] = profile
    session["profile_json"] = me_resp.text
    return profile


def _hydrate_status(access_token: str, user_id: int) -> dict[str, Any]:
    resp = _fetch_user_status(access_token, user_id)
    _record_api_call("GET", _status_url(user_id), resp)
    status = _status_from_get_response(resp)
    session["user_status"] = status
    session["user_status_json"] = resp.text
    return status


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Zulip OAuth client showcase</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { max-width: 48rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85em; }
    pre { background: #1112; padding: 0.75rem 1rem; overflow: auto; border-radius: 6px; white-space: pre-wrap; word-break: break-all; }
    .card { border: 1px solid #8884; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
    .err { border-color: #c33; background: #c331; }
    .ok { border-color: #2a6; background: #2a61; }
    a.btn, button.btn {
      display: inline-block; margin: 0.25rem 0.5rem 0.25rem 0;
      padding: 0.5rem 0.9rem; border-radius: 6px; border: 1px solid #8886;
      background: #246; color: #fff; text-decoration: none; cursor: pointer; font: inherit;
    }
    a.btn.secondary, button.btn.secondary { background: transparent; color: inherit; }
    dt { font-weight: 600; margin-top: 0.5rem; }
    dd { margin: 0.15rem 0 0.5rem 0; }
    .muted { opacity: 0.75; font-size: 0.9em; }
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
  {% if notice %}
  <div class="card ok"><strong>OK:</strong> {{ notice }}</div>
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
    <p>
      <a class="btn secondary" href="{{ url_for('refresh_profile') }}">Re-fetch /users/me</a>
      {% if tokens and tokens.refresh_token %}
      <a class="btn secondary" href="{{ url_for('refresh_tokens') }}">Refresh access token</a>
      {% endif %}
      <a class="btn secondary" href="{{ url_for('logout') }}">Log out</a>
    </p>
  </div>

  <div class="card">
    <h3>User status (write API)</h3>
    <p class="muted">
      Bearer token calls
      <code>GET /api/v1/users/{{ profile.user_id }}/status</code> and
      <code>POST /api/v1/users/me/status</code>.
      Toggle flips between empty status and
      <code>{{ showcase_status_text }}</code> + <code>:{{ showcase_emoji_name }}:</code>.
    </p>
    <dl>
      <dt>status_text</dt>
      <dd><code>{{ user_status.status_text if user_status and user_status.status_text else '(empty)' }}</code></dd>
      <dt>emoji_name</dt>
      <dd><code>{{ user_status.emoji_name if user_status and user_status.emoji_name else '(none)' }}</code></dd>
    </dl>
    <p>
      <a class="btn" href="{{ url_for('toggle_status') }}">Toggle status</a>
      <a class="btn secondary" href="{{ url_for('refresh_status') }}">Re-fetch status</a>
    </p>
    {% if user_status_json %}
    <h4>Last status response</h4>
    <pre>{{ user_status_json }}</pre>
    {% endif %}
  </div>

  {% if last_api_call %}
  <div class="card">
    <h3>Last API call</h3>
    <p>
      <code>{{ last_api_call.method }}</code>
      <code>{{ last_api_call.url }}</code>
      → <strong>{{ last_api_call.status_code }}</strong>
    </p>
    <pre>{{ last_api_call.body }}</pre>
  </div>
  {% endif %}

  <div class="card">
    <h3>Stored tokens</h3>
    <p class="muted">
      Flask session + <code>.token_cache.json</code> (gitignored). Access tokens expire
      after <code>expires_in</code> seconds on the Zulip server (default 36000).
    </p>
    <dl>
      <dt>token_type</dt><dd><code>{{ tokens.token_type }}</code></dd>
      <dt>scope</dt><dd><code>{{ tokens.scope }}</code></dd>
      <dt>expires_in</dt><dd><code>{{ tokens.expires_in }}</code></dd>
      <dt>obtained_at (unix)</dt><dd><code>{{ tokens.obtained_at }}</code></dd>
      <dt>expires_at (unix)</dt><dd><code>{{ tokens.expires_at }}</code></dd>
      <dt>access_token</dt>
      <dd><pre>{{ tokens.access_token }}</pre></dd>
      <dt>refresh_token</dt>
      <dd>
        {% if tokens.refresh_token %}
        <pre>{{ tokens.refresh_token }}</pre>
        {% else %}
        <em>(not issued in token response)</em>
        {% endif %}
      </dd>
    </dl>
    <h4>Raw <code>/o/token/</code> JSON</h4>
    <pre>{{ tokens_raw_json }}</pre>
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


@app.get("/")
def index() -> str:
    tokens = _load_tokens()
    profile = session.get("profile")
    if tokens and not profile and tokens.get("access_token"):
        profile = _hydrate_profile(tokens["access_token"])

    if tokens and profile and profile.get("user_id") and "user_status" not in session:
        _hydrate_status(tokens["access_token"], int(profile["user_id"]))

    tokens_raw_json = ""
    if tokens:
        tokens_raw_json = json.dumps(tokens.get("raw") or tokens, indent=2)

    return render_template_string(
        PAGE,
        configured=_configured(),
        realm=ZULIP_REALM_URL,
        redirect_uri=REDIRECT_URI,
        profile=profile,
        profile_json=session.get("profile_json"),
        tokens=tokens,
        tokens_raw_json=tokens_raw_json,
        user_status=session.get("user_status") or {},
        user_status_json=session.get("user_status_json"),
        last_api_call=session.get("last_api_call"),
        showcase_status_text=SHOWCASE_STATUS_TEXT,
        showcase_emoji_name=SHOWCASE_EMOJI_NAME,
        error=request.args.get("error"),
        notice=request.args.get("notice"),
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
    if not token_payload.get("access_token"):
        return redirect(url_for("index", error="No access_token in token response"))

    tokens = _store_tokens(token_payload)
    profile = _hydrate_profile(tokens["access_token"])
    if profile is None:
        return redirect(url_for("index", error="users/me failed after token exchange"))
    _hydrate_status(tokens["access_token"], int(profile["user_id"]))
    return redirect(url_for("index", notice="Signed in; tokens stored."))


@app.get("/refresh-tokens")
def refresh_tokens() -> Any:
    tokens = _load_tokens()
    if not tokens or not tokens.get("refresh_token"):
        return redirect(url_for("index", error="No refresh_token stored"))

    token_resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=30,
    )
    if not token_resp.ok:
        return redirect(
            url_for(
                "index",
                error=f"Refresh failed ({token_resp.status_code}): {token_resp.text[:300]}",
            )
        )

    payload = token_resp.json()
    if not payload.get("refresh_token") and tokens.get("refresh_token"):
        payload["refresh_token"] = tokens["refresh_token"]
    _store_tokens(payload)
    return redirect(url_for("index", notice="Access token refreshed."))


@app.get("/refresh-profile")
def refresh_profile() -> Any:
    tokens = _load_tokens()
    if not tokens or not tokens.get("access_token"):
        return redirect(url_for("index", error="No access_token stored"))

    profile = _hydrate_profile(tokens["access_token"])
    if profile is None:
        last = session.get("last_api_call") or {}
        return redirect(
            url_for(
                "index",
                error=f"users/me failed ({last.get('status_code')}): {(last.get('body') or '')[:300]}",
            )
        )
    return redirect(url_for("index", notice="Profile re-fetched."))


@app.get("/refresh-status")
def refresh_status() -> Any:
    tokens = _load_tokens()
    profile = session.get("profile")
    if not tokens or not tokens.get("access_token"):
        return redirect(url_for("index", error="No access_token stored"))
    if not profile or not profile.get("user_id"):
        return redirect(url_for("index", error="No profile/user_id; re-fetch /users/me first"))

    _hydrate_status(tokens["access_token"], int(profile["user_id"]))
    last = session.get("last_api_call") or {}
    if last.get("status_code") != 200:
        return redirect(
            url_for(
                "index",
                error=f"status get failed ({last.get('status_code')}): {(last.get('body') or '')[:300]}",
            )
        )
    return redirect(url_for("index", notice="Status re-fetched."))


@app.get("/toggle-status")
def toggle_status() -> Any:
    """Flip between empty status and a fixed showcase status via bearer token."""
    tokens = _load_tokens()
    profile = session.get("profile")
    if not tokens or not tokens.get("access_token"):
        return redirect(url_for("index", error="No access_token stored"))
    if not profile or not profile.get("user_id"):
        return redirect(url_for("index", error="No profile/user_id; re-fetch /users/me first"))

    access_token = tokens["access_token"]
    user_id = int(profile["user_id"])

    current = _hydrate_status(access_token, user_id)
    current_text = (current.get("status_text") or "").strip()
    turning_on = current_text != SHOWCASE_STATUS_TEXT

    if turning_on:
        payload: dict[str, Any] = {
            "status_text": SHOWCASE_STATUS_TEXT,
            "emoji_name": SHOWCASE_EMOJI_NAME,
            "emoji_code": SHOWCASE_EMOJI_CODE,
            "reaction_type": SHOWCASE_REACTION_TYPE,
            "away": "false",
        }
        notice = f'Status set to "{SHOWCASE_STATUS_TEXT}".'
    else:
        # Clear text + emoji (empty strings are the documented clear signal).
        payload = {
            "status_text": "",
            "emoji_name": "",
            "emoji_code": "",
            "reaction_type": "",
            "away": "false",
        }
        notice = "Status cleared."

    set_resp = _set_user_status(access_token, payload)
    _record_api_call("POST", _update_status_url(), set_resp)
    if not set_resp.ok:
        return redirect(
            url_for(
                "index",
                error=f"status update failed ({set_resp.status_code}): {set_resp.text[:300]}",
            )
        )

    # Re-read so the UI shows server truth after the write.
    _hydrate_status(access_token, user_id)
    return redirect(url_for("index", notice=notice))


@app.get("/logout")
def logout() -> Any:
    session.clear()
    _clear_token_cache()
    return redirect(url_for("index"))


@app.get("/health")
def health() -> dict[str, Any]:
    tokens = _load_tokens()
    return {
        "status": "ok",
        "realm": ZULIP_REALM_URL,
        "has_access_token": bool(tokens and tokens.get("access_token")),
        "has_refresh_token": bool(tokens and tokens.get("refresh_token")),
    }


def main() -> None:
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5050"))
    print(f"Zulip realm: {ZULIP_REALM_URL}")
    print(f"Authorize:   {AUTHORIZE_URL}")
    print(f"Token:       {TOKEN_URL}")
    print(f"Callback:    {REDIRECT_URI}")
    print(f"Token cache: {TOKEN_CACHE_PATH}")
    print(f"Open:        http://{host}:{port}/")
    app.run(host=host, port=port, debug=True, threaded=True)


if __name__ == "__main__":
    main()
