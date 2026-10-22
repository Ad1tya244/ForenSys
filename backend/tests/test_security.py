"""
Security regression tests: WebSocket authentication, token-expiry enforcement, CORS origin policy, JWT secret.
Run:  backend/.venv/bin/python -m unittest discover -s backend/tests -p "test_security.py" -t backend
"""

import asyncio
import json
import os
import re
import sys
import time
import unittest
from datetime import timedelta
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import auth_utils
import main
from fastapi import HTTPException


class FakeWS:
    """Minimal stand-in for a Starlette WebSocket."""

    def __init__(self, first_message=None, delay=0.0):
        self._first, self._delay = first_message, delay
        self.closed_with = None
        self.sent = []

    async def receive_text(self):
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._first is None:
            await asyncio.sleep(60)
        return self._first

    async def close(self, code=1000):
        self.closed_with = code

    async def send_text(self, text):
        self.sent.append(text)


ACTIVE_USER = {"id": "u1", "status": "active", "role": "analyst", "permissions": []}


def auth_msg(token):
    return json.dumps({"type": "auth", "token": token})


class WebSocketAuthTests(unittest.TestCase):
    def run_auth(self, ws, user=ACTIVE_USER):
        with mock.patch.object(main, "find_user_by_id", return_value=user):
            with mock.patch.object(main, "_WS_AUTH_TIMEOUT_SEC", 0.3):
                return asyncio.run(main._ws_authenticate(ws))

    def test_valid_token_is_accepted_and_returns_expiry(self):
        token = auth_utils.create_access_token({"sub": "u1"})
        ws = FakeWS(auth_msg(token))
        exp = self.run_auth(ws)
        self.assertIsNotNone(exp)
        self.assertGreater(exp, time.time())
        self.assertIsNone(ws.closed_with)

    def test_no_message_is_rejected(self):
        ws = FakeWS(first_message=None)   # client connects and says nothing
        self.assertIsNone(self.run_auth(ws))
        self.assertEqual(ws.closed_with, 4003)

    def test_garbage_and_wrong_shape_are_rejected(self):
        for msg in ("not json", json.dumps({"type": "auth"}), json.dumps({"token": "x"}), json.dumps([1, 2]),
                    auth_msg("not.a.jwt"), auth_msg(None)):
            ws = FakeWS(msg)
            self.assertIsNone(self.run_auth(ws), msg)
            self.assertEqual(ws.closed_with, 4003, msg)

    def test_refresh_token_cannot_be_used_for_the_stream(self):
        ws = FakeWS(auth_msg(auth_utils.create_refresh_token({"sub": "u1"})))
        self.assertIsNone(self.run_auth(ws))
        self.assertEqual(ws.closed_with, 4003)

    def test_expired_token_is_rejected(self):
        token = auth_utils.create_access_token({"sub": "u1"}, expires_delta=timedelta(seconds=-5))
        ws = FakeWS(auth_msg(token))
        self.assertIsNone(self.run_auth(ws))
        self.assertEqual(ws.closed_with, 4003)

    def test_token_signed_with_the_old_public_default_secret_is_rejected(self):
        import jwt
        forged = jwt.encode({"sub": "u1", "type": "access", "exp": time.time() + 600},
                            auth_utils._LEGACY_DEFAULT_SECRET, algorithm="HS256")
        ws = FakeWS(auth_msg(forged))
        self.assertIsNone(self.run_auth(ws))
        self.assertEqual(ws.closed_with, 4003)

    def test_inactive_or_unknown_user_is_rejected(self):
        token = auth_utils.create_access_token({"sub": "u1"})
        for user in (None, {**ACTIVE_USER, "status": "disabled"}):
            ws = FakeWS(auth_msg(token))
            self.assertIsNone(self.run_auth(ws, user=user))
            self.assertEqual(ws.closed_with, 4003)

    def test_broadcast_drops_clients_whose_token_expired_and_keeps_valid_ones(self):
        expired, valid = FakeWS(), FakeWS()
        main._clients[:] = [expired, valid]
        main._client_exp.clear()
        main._client_exp[expired] = time.time() - 1
        main._client_exp[valid] = time.time() + 600
        try:
            asyncio.run(main._broadcast({"hello": "world"}))
            self.assertEqual(expired.closed_with, 4003)
            self.assertEqual(expired.sent, [])
            self.assertEqual(len(valid.sent), 1)
            self.assertEqual(main._clients, [valid])
        finally:
            main._clients.clear()
            main._client_exp.clear()


class WebSocketRouteTests(unittest.TestCase):
    """Drives the real /ws route through the ASGI interface (no sockets needed)."""

    SECRET_SNAPSHOT = {"all_alerts": [{"id": "A1", "title": "secret telemetry"}]}

    def drive(self, client_messages, query_string=b""):
        async def run():
            incoming, outgoing = asyncio.Queue(), []
            await incoming.put({"type": "websocket.connect"})
            for m in client_messages:
                await incoming.put({"type": "websocket.receive", "text": m})
            await incoming.put({"type": "websocket.disconnect", "code": 1000})

            async def receive():
                return await incoming.get()

            async def send(message):
                outgoing.append(message)

            scope = {"type": "websocket", "path": "/ws", "raw_path": b"/ws", "query_string": query_string, "headers": [],
                     "client": ("203.0.113.9", 4444), "server": ("localhost", 8000), "scheme": "ws",
                     "subprotocols": [], "asgi": {"version": "3.0"}}
            await main.app(scope, receive, send)
            return outgoing
        main._latest_snapshot = self.SECRET_SNAPSHOT
        with mock.patch.object(main, "find_user_by_id", return_value=ACTIVE_USER):
            try:
                return asyncio.run(run())
            finally:
                main._latest_snapshot = {}
                main._clients.clear()
                main._client_exp.clear()

    def texts(self, outgoing):
        return [m["text"] for m in outgoing if m["type"] == "websocket.send" and m.get("text")]

    def test_unauthenticated_client_never_receives_the_snapshot(self):
        out = self.drive([])                                  # connects, sends nothing
        self.assertEqual(self.texts(out), [])
        self.assertTrue(any(m["type"] == "websocket.close" and m.get("code") == 4003 for m in out))

    def test_bad_token_never_receives_the_snapshot(self):
        out = self.drive([auth_msg("forged.token.value")])
        self.assertEqual(self.texts(out), [])
        self.assertTrue(any(m["type"] == "websocket.close" and m.get("code") == 4003 for m in out))

    def test_token_in_query_string_is_ignored(self):
        # The old behaviour (token in the URL) must not authenticate anything any more.
        token = auth_utils.create_access_token({"sub": "u1"})
        out = self.drive([], query_string=f"token={token}".encode())
        self.assertEqual(self.texts(out), [], "a valid token in the URL must not authenticate the stream")
        self.assertTrue(any(m["type"] == "websocket.close" and m.get("code") == 4003 for m in out))

    def test_valid_token_receives_the_snapshot(self):
        out = self.drive([auth_msg(auth_utils.create_access_token({"sub": "u1"}))])
        texts = self.texts(out)
        self.assertEqual(len(texts), 1)
        self.assertEqual(json.loads(texts[0]), self.SECRET_SNAPSHOT)


class LoginTests(unittest.TestCase):
    """There must be no hard-coded or default credentials anywhere in the login path."""

    BACKDOOR_PASSWORDS = ("operator", "password", "admin", "password123", "operator123")

    def user(self, **over):
        u = {"id": "u1", "name": "Real User", "email": "real@forensys.in", "role": "admin", "department": "Security",
             "status": "active", "permissions": ["view_alerts"], "salt": "",
             "password_hash": auth_utils.hash_password_bcrypt("A-Long-Real-Passphrase-42")}
        u.update(over)
        return u

    def login(self, password, user):
        from fastapi import Response
        from schemas import LoginModel
        with mock.patch.object(main, "find_user_by_email", return_value=user):
            return main.api_login(LoginModel(email=user["email"], password=password), Response())

    def test_real_password_works(self):
        out = self.login("A-Long-Real-Passphrase-42", self.user())
        self.assertTrue(out["access_token"])
        self.assertNotIn("password_hash", out["user"])

    def test_hard_coded_passwords_do_not_log_anyone_in(self):
        for pw in self.BACKDOOR_PASSWORDS:
            with self.assertRaises(HTTPException) as e:
                self.login(pw, self.user())
            self.assertEqual(e.exception.status_code, 401, pw)

    def test_account_without_a_password_hash_cannot_log_in(self):
        for pw in self.BACKDOOR_PASSWORDS + ("",):
            with self.assertRaises(HTTPException) as e:
                self.login(pw, self.user(password_hash=""))
            self.assertEqual(e.exception.status_code, 401, pw)

    def test_inactive_account_is_rejected_even_with_the_right_password(self):
        with self.assertRaises(HTTPException) as e:
            self.login("A-Long-Real-Passphrase-42", self.user(status="inactive"))
        self.assertEqual(e.exception.status_code, 401)

    def test_json_fallback_never_assigns_a_default_password(self):
        legacy = [{"id": "7", "name": "Legacy", "email": "legacy@forensys.in", "role": "analyst", "status": "active", "permissions": []}]
        with mock.patch.object(main, "get_db_connection", side_effect=RuntimeError("db down")), \
             mock.patch.object(main, "load_users_from_file", return_value=legacy):
            by_email = main.find_user_by_email("legacy@forensys.in")
            by_id = main.find_user_by_id("7")
        for u in (by_email, by_id):
            self.assertEqual(u["password_hash"], "")


class CorsPolicyTests(unittest.TestCase):
    rx = re.compile(main._LAN_ORIGIN_REGEX)

    def test_local_and_lan_origins_allowed(self):
        for origin in ("http://localhost:3000", "http://127.0.0.1:3000", "http://192.168.1.4:3000",
                       "http://10.0.0.7:3000", "http://172.20.1.2:3000", "http://adityas-macbook-air-m4.local:3000"):
            self.assertTrue(self.rx.match(origin), origin)

    def test_internet_origins_blocked(self):
        for origin in ("https://evil.example.com", "http://192.168.1.4.evil.com", "http://localhost.evil.com",
                       "https://attacker.io:3000", "http://172.32.0.1:3000", "http://8.8.8.8:3000"):
            self.assertFalse(self.rx.match(origin), origin)


class JwtSecretTests(unittest.TestCase):
    def test_secret_is_strong_and_not_the_old_public_default(self):
        self.assertGreaterEqual(len(auth_utils.JWT_SECRET_KEY), 32)
        self.assertNotEqual(auth_utils.JWT_SECRET_KEY, auth_utils._LEGACY_DEFAULT_SECRET)


if __name__ == "__main__":
    unittest.main()
