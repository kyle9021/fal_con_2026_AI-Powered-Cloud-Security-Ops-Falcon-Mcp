"""Minimal, read-only CrowdStrike Falcon API client — Python stdlib only.

Why this exists
---------------
The Falcon MCP server is how the *model* talks to Falcon. This module is how the
*harness* talks to Falcon: hooks and the preflight doctor are plain shell/Python,
they run before or around the model, so they cannot call MCP tools.

Design constraints (deliberate):
  * stdlib only — no pip install, works on any Python 3.9+.
  * GET requests only, plus the OAuth2 token POST. There is no code path in this
    file that can create, modify, or delete anything in your tenant.
  * Secrets are read from the environment and never logged, printed, or included
    in an exception message.
  * Every call is bounded by a timeout so a slow API can never hang your shell.
"""

from __future__ import annotations

import base64
import json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# US-1. Every other region (including both GovClouds, which cannot be
# autodiscovered) requires FALCON_BASE_URL -- see the table in env.example.
DEFAULT_BASE_URL = "https://api.crowdstrike.com"

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "falcon-mcp-harness/1.0"


class FalconError(Exception):
    """An API or configuration problem. Never carries credential material."""


def load_dotenv(path: str) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Existing environment variables always win, so a value exported in your shell
    or injected by a secret manager is never silently overridden by a file.
    """
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


class FalconClient:
    """Read-only Falcon API client with lazy OAuth2 token acquisition."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.client_id = os.environ.get("FALCON_CLIENT_ID", "")
        self._client_secret = os.environ.get("FALCON_CLIENT_SECRET", "")
        self.base_url = (os.environ.get("FALCON_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.member_cid = os.environ.get("FALCON_MEMBER_CID", "")
        self.timeout = timeout
        self._token: str | None = None
        self._token_lock = threading.Lock()
        self._cid: str = ""

        if not self.client_id or not self._client_secret:
            raise FalconError(
                "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are not set. "
                "Copy env.example to .env and fill them in."
            )

    # -- auth ---------------------------------------------------------------

    def _authenticate(self) -> str:
        """Exchange client credentials for a bearer token."""
        form = {"client_id": self.client_id, "client_secret": self._client_secret}
        if self.member_cid:
            form["member_cid"] = self.member_cid

        request = urllib.request.Request(
            f"{self.base_url}/oauth2/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            # 403 here almost always means bad keys or wrong region -- surface
            # that guess, but never the credential values themselves.
            raise FalconError(
                f"Falcon authentication failed (HTTP {exc.code}). "
                f"Check your client ID/secret and that FALCON_BASE_URL ({self.base_url}) "
                "matches your tenant's region."
            ) from None
        except urllib.error.URLError as exc:
            raise FalconError(f"Cannot reach {self.base_url}: {exc.reason}") from None

        token = payload.get("access_token")
        if not token:
            raise FalconError("Falcon authentication returned no access token.")
        # CID lives in the JWT `sub` claim
        try:
            parts = token.split(".")
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            self._cid = json.loads(base64.urlsafe_b64decode(padded)).get("sub", "")
        except Exception:
            pass
        return token

    @property
    def cid(self) -> str:
        """Customer ID captured from the X-CS-CID response header."""
        return self._cid

    @property
    def token(self) -> str:
        with self._token_lock:
            if self._token is None:
                self._token = self._authenticate()
            return self._token

    # -- requests -----------------------------------------------------------

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Issue an authenticated GET. Returns the parsed JSON body.

        Raises FalconError on transport failure. HTTP error *statuses* are
        returned as a payload with an "errors" key so callers can distinguish a
        missing API scope (403) from a hard failure and degrade gracefully.

        Handles two recoverable failures transparently:
          * 401 — token expired (Falcon tokens TTL 30 min). Re-authenticates once.
          * 429 — rate limited. Sleeps on Retry-After header, retries once.
        """
        query = ""
        if params:
            present = {key: value for key, value in params.items() if value is not None}
            query = "?" + urllib.parse.urlencode(present, doseq=True)

        for attempt in range(3):
            request = urllib.request.Request(
                f"{self.base_url}{path}{query}",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    with self._token_lock:
                        self._token = self._authenticate()
                    continue
                if exc.code == 429 and attempt < 2:
                    retry_after = int(exc.headers.get("Retry-After", "5"))
                    jitter = random.uniform(0, min(retry_after, 5))
                    time.sleep(min(retry_after + jitter, 60))
                    continue
                body: dict[str, Any] = {}
                try:
                    body = json.load(exc)
                except Exception:
                    pass
                body.setdefault("errors", [{"code": exc.code, "message": exc.reason}])
                body["_status"] = exc.code
                return body
            except urllib.error.URLError as exc:
                if attempt < 2:
                    time.sleep(min(3 * (attempt + 1), 15))
                    continue
                raise FalconError(f"Request to {path} failed: {exc.reason}") from None
            except (TimeoutError, OSError) as exc:
                if attempt < 2:
                    time.sleep(min(3 * (attempt + 1), 15))
                    continue
                raise FalconError(f"Request to {path} timed out: {exc}") from None
        # Unreachable, but keeps the type checker happy.
        raise FalconError(f"Request to {path} failed after retries")

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def total(payload: dict[str, Any]) -> int | None:
        """Pull meta.pagination.total out of a response, or None if absent.

        None means "could not determine" (usually a missing API scope) and is
        deliberately distinct from 0, which means "genuinely nothing found".
        """
        try:
            return int(payload["meta"]["pagination"]["total"])
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def denied(payload: dict[str, Any]) -> bool:
        """True when a signal is unavailable to this tenant or API client.

        Covers three real-world cases that all mean "skip this metric, don't
        alarm the user":
          401/403 -- the API client is missing the required scope.
          404     -- the feature is not licensed or enabled on this tenant.
                     CrowdScore, for example, 404s on tenants without it.

        Deliberately NOT covered: 429 and 5xx. Those mean "ask again later", not
        "you cannot have this", and treating them as a denial would let a rate
        limit render as a permanent gap. Use `errored()` for them -- and note
        that a caller which checks neither turns a rate limit into a real zero,
        which is the worst failure mode this harness has.
        """
        return payload.get("_status") in (401, 403, 404)

    @staticmethod
    def errored(payload: dict[str, Any]) -> bool:
        """True when the request failed for a reason that is nobody's answer.

        429 (rate limited) and 5xx (server-side) are transient. They are neither
        a denial nor a result, and the distinction is load-bearing:

          * A denial is stable. Reporting it as a gap is correct and final.
          * An error is not. The same query may succeed in a minute.
          * **Neither is zero.** A caller that checks `denied()` alone lets a 500
            fall through to `payload.get("resources") or []` and reports a
            confident, green, fully-paginated "0 findings" for a query that never
            ran. That artifact -- authoritative, wrong, and CI-passing -- is
            precisely what this distinction exists to prevent.

        So an errored response must set a gap *and* fail the run (exit 1), never
        contribute a 0 to a metric.
        """
        status = payload.get("_status")
        if not isinstance(status, int):
            return False
        return status == 429 or 500 <= status <= 599

