import base64
import hashlib
import hmac
import json
import math
import os
import time
from typing import Any, Dict, Optional


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    s = data.encode("ascii")
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


_CACHED_SECRET: Optional[str] = None
_CACHED_PASSWORD_FINGERPRINT: Optional[str] = None
_REVOKED_BEFORE_UNIX: int = 0
LEGACY_JWT_SECRET = "dev-insecure-jwt-secret"


def compute_password_fingerprint(password_hash: Optional[str]) -> Optional[str]:
    """根据管理员 password_hash 计算短指纹，用于在改密后自动令旧 JWT 失效。"""
    cleaned = (password_hash or "").strip()
    if not cleaned:
        return None
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]


def set_admin_password_fingerprint(password_hash: Optional[str]) -> None:
    """设置当前进程缓存的管理员密码哈希指纹。"""
    global _CACHED_PASSWORD_FINGERPRINT
    _CACHED_PASSWORD_FINGERPRINT = compute_password_fingerprint(password_hash)


def revoke_admin_jwts(before_unix: Optional[int] = None) -> int:
    """吊销指定时间戳（默认当前时刻）及之前签发的所有 Admin JWT。"""
    global _REVOKED_BEFORE_UNIX
    target = int(before_unix) if before_unix is not None else int(time.time())
    if target > _REVOKED_BEFORE_UNIX:
        _REVOKED_BEFORE_UNIX = target
    return _REVOKED_BEFORE_UNIX


def set_jwt_secret(secret: str) -> None:
    """设置当前进程使用的 JWT 签名密钥（通常由启动阶段从 DB/文件加载后注入）。"""

    global _CACHED_SECRET, _CACHED_PASSWORD_FINGERPRINT, _REVOKED_BEFORE_UNIX
    secret = (secret or "").strip()
    if not secret or secret == LEGACY_JWT_SECRET:
        raise ValueError("A trusted JWT signing secret is required")
    if _CACHED_SECRET != secret:
        _CACHED_PASSWORD_FINGERPRINT = None
        _REVOKED_BEFORE_UNIX = 0
    _CACHED_SECRET = secret


def _jwt_secret() -> str:
    """获取 JWT 签名密钥。

    显式环境变量优先，否则使用启动或初始化时加载的持久化密钥。
    未就绪时拒绝签发和校验，不提供默认或进程随机密钥。
    """

    secret = (os.getenv("JWT_SECRET") or "").strip() or _CACHED_SECRET
    if not secret or secret == LEGACY_JWT_SECRET:
        raise RuntimeError("JWT signing secret is not initialized")
    return secret


def issue_jwt(payload: Dict[str, Any], *, expires_in_seconds: int = 7 * 24 * 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}

    now = int(time.time())
    full_payload = dict(payload)
    # iat 精度是秒，吊销判断用的是 iat <= _REVOKED_BEFORE_UNIX。
    # 吊销后同一秒内签发的新令牌（改密码返回的令牌、退出后立刻重新登录）会被误判为已吊销，
    # 所以默认 iat 至少取吊销时间点之后的那一秒。
    full_payload.setdefault("iat", max(now, _REVOKED_BEFORE_UNIX + 1) if _REVOKED_BEFORE_UNIX > 0 else now)
    full_payload.setdefault("exp", now + int(expires_in_seconds))
    if str(full_payload.get("role", "")).lower() == "admin" and _CACHED_PASSWORD_FINGERPRINT:
        full_payload.setdefault("pwd_fp", _CACHED_PASSWORD_FINGERPRINT)

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(full_payload, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(_jwt_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    if not token or token.count(".") != 2:
        return None

    try:
        header_b64, payload_b64, sig_b64 = token.split(".", 2)
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return None
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(
            _jwt_secret().encode("utf-8"), signing_input, hashlib.sha256
        ).digest()

        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if not isinstance(payload, dict):
            return None

        exp = payload.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            return None
        if time.time() >= exp:
            return None

        iat = payload.get("iat")
        if _REVOKED_BEFORE_UNIX > 0:
            if isinstance(iat, bool) or not isinstance(iat, (int, float)) or int(iat) <= _REVOKED_BEFORE_UNIX:
                return None

        if str(payload.get("role", "")).lower() == "admin" and _CACHED_PASSWORD_FINGERPRINT:
            token_fp = payload.get("pwd_fp")
            if token_fp != _CACHED_PASSWORD_FINGERPRINT:
                return None

        return payload
    except Exception:
        return None


def is_admin_jwt(token: str) -> bool:
    payload = decode_jwt(token)
    if not payload:
        return False
    return str(payload.get("role", "")).lower() == "admin"
