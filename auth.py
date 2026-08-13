"""
auth.py
--------
Authentication & rate-limiting core for PropGuard AI, implementing
SECTION 2 of the PRD:

  Mobile App (Flutter/Kotlin)
        │  1. Authenticates via Firebase Auth (Phone OTP / Email+Password)
        ▼
  Firebase Auth  ──issues──▶  short-lived JWT ID Token
        │  2. Client sends: Authorization: Bearer <JWT>
        ▼
  FastAPI Proxy Backend  ──validates signature, rate-limits──▶  AI/SOS pipelines

Every protected endpoint depends on `get_current_user`, which verifies the
Firebase ID token and returns the decoded claims (uid, email/phone, etc.).
No endpoint trusts a client-supplied `user_id` anymore — the authenticated
`uid` is the single source of truth for who is making the request.
"""

from __future__ import annotations

import logging

import firebase_admin
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from firebase_admin import auth as firebase_auth
from firebase_admin import credentials
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings

logger = logging.getLogger("propguard.auth")
settings = get_settings()

_security = HTTPBearer(auto_error=True)


def init_firebase() -> None:
    """
    Initializes the Firebase Admin SDK once at startup using a service
    account JSON file. The path is provided via FIREBASE_SERVICE_ACCOUNT_PATH
    in .env and must NEVER be committed to version control.
    """
    if firebase_admin._apps:
        return
    cred = credentials.Certificate(settings.firebase_service_account_path)
    firebase_admin.initialize_app(cred)
    logger.info("Firebase Admin SDK initialized.")


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(_security),
) -> dict:
    """
    FastAPI dependency: validates the Bearer JWT issued by Firebase Auth on
    every protected route. Raises 401 on any invalid/expired/malformed token.

    Returns the decoded token claims, most importantly:
      - uid    : the stable Firebase user id — used as our internal user_id
      - email  : if the user signed up with email/password
      - phone_number : if the user signed up with phone OTP
    """
    token = credentials.credentials
    try:
        decoded = firebase_auth.verify_id_token(token, check_revoked=True)
        # Stash uid on request.state so the rate limiter can key by user
        # instead of shared IP (see _rate_limit_key below).
        request.state.uid = decoded["uid"]
        return decoded
    except firebase_auth.RevokedIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked — please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except firebase_auth.ExpiredIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired — please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as exc:  # noqa: BLE001 — any other verification failure is a 401, not a 500
        logger.warning("JWT verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_uid(user: dict = Depends(get_current_user)) -> str:
    """Convenience dependency when a route only needs the authenticated uid string."""
    return user["uid"]


# ----------------------------------------------------------------------
# Rate limiting (slowapi, Redis-backed in production; in-memory in dev)
# ----------------------------------------------------------------------

def _rate_limit_key(request: Request) -> str:
    """
    Key rate limits by the Firebase uid already resolved onto the request
    state by `get_current_user` (see routers — auth runs before the limiter
    check on protected routes), falling back to IP address for any request
    that hasn't been authenticated yet. This stops one user from draining
    shared quota behind a NAT/office IP while still rate-limiting anonymous
    traffic sanely.
    """
    uid = getattr(request.state, "uid", None)
    return uid if uid else get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key, storage_uri=settings.redis_url)
