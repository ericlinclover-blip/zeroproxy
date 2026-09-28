"""密钥与凭据生成。

- VLESS UUID: 由 用户名+密码 经 SHA256 确定性派生 (技术文档 §2.2: 16 字节身份字段),
  保证重新生成配置时 UUID 稳定不变, 客户端无需重新导入。
- Reality: ed25519 密钥对 (技术文档 §7.2.1 密钥体系), 首次部署生成, 之后持久化。
- 管理密码: PBKDF2-SHA256 加盐哈希, 不存明文。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid as _uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def derive_uuid(username: str, password: str) -> str:
    """确定性派生 VLESS UUID (16 bytes, UUID 格式)。"""
    digest = hashlib.sha256(f"zeroproxy:vless:{username}:{password}".encode()).digest()
    return str(_uuid.UUID(bytes=digest[:16]))


def new_reality_keys() -> tuple[str, str, str]:
    """生成 Reality ed25519 密钥对。

    返回 (private_key_b64, public_key_b64, short_id_hex)。
    Xray 配置使用标准 base64; 分享链接需 base64url (见 share_links.py)。
    """
    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Xray 与客户端链接 (pbk) 均使用 base64url 无填充格式
    private_b64 = base64.urlsafe_b64encode(private_raw).decode().rstrip("=")
    public_b64 = base64.urlsafe_b64encode(public_raw).decode().rstrip("=")
    return private_b64, public_b64, secrets.token_hex(4)


def new_token(nbytes: int = 24) -> str:
    """生成 URL 安全随机令牌 (订阅令牌 / 会话令牌)。"""
    return secrets.token_urlsafe(nbytes)


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return f"pbkdf2${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    parts = stored.split("$")
    if len(parts) != 3 or parts[0] != "pbkdf2":
        return False
    try:
        salt = bytes.fromhex(parts[1])
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)
