"""密钥与凭据生成。

- VLESS UUID: 由 用户名+密码 经 SHA256 确定性派生 (技术文档 §2.2: 16 字节身份字段),
  保证重新生成配置时 UUID 稳定不变, 客户端无需重新导入。
- Reality: X25519 密钥对 (Xray REALITY 使用的曲线), 首次部署生成, 之后持久化。
- 管理密码: PBKDF2-SHA256 加盐哈希, 不存明文。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import uuid as _uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def derive_uuid(username: str, password: str) -> str:
    """确定性派生 VLESS UUID (16 bytes, UUID 格式)。"""
    digest = hashlib.sha256(f"zeroproxy:vless:{username}:{password}".encode()).digest()
    return str(_uuid.UUID(bytes=digest[:16]))


def _b64url(raw: bytes) -> str:
    """base64url 无填充 —— Xray 配置、分享链接 `pbk`、以及 `xray x25519` 都用这个格式。"""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    """解析 base64url (容忍缺少填充, 同时接受标准 base64 字符集)。"""
    text = value.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def new_reality_keys() -> tuple[str, str, str]:
    """生成 Reality X25519 密钥对。

    返回 (private_key_b64, public_key_b64, short_id_hex)。
    Xray 配置使用标准 base64; 分享链接需 base64url (见 share_links.py)。

    必须是 X25519: REALITY 握手基于 TLS 1.3 的 key_share 曲线, 服务端私钥要能
    与客户端的 X25519 临时公钥做 ECDH。用 Ed25519 (v2.3.2 及更早的写法) 生成的
    密钥对会让 Xray 侧认证必然失败, 客户端回落到真实网站 —— 表现就是"节点运行中
    但全部不通"。
    """
    key = X25519PrivateKey.generate()
    return _b64url(key.private_bytes_raw()), _b64url(key.public_key().public_bytes_raw()), secrets.token_hex(4)


def reality_public_from_private(private_key: str) -> str:
    """由私钥推导 X25519 公钥 (base64url 无填充)。密钥不合法时抛 ValueError。"""
    raw = _b64url_decode(private_key)
    if len(raw) != 32:
        raise ValueError(f"Reality 私钥应为 32 字节, 实际 {len(raw)}")
    return _b64url(X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes_raw())


def reality_key_valid(private_key: str, public_key: str) -> bool:
    """state 里的 Reality 密钥对是否是同一对合法 X25519 密钥。

    只做长度/格式检查是不够的: 服务端用私钥握手, 客户端用 `pbk` (公钥) 校验,
    两者对不上时 Xray 不会报错, 只是每一次握手都失败。
    """
    if not private_key or not public_key:
        return False
    try:
        derived = reality_public_from_private(private_key)
    except (ValueError, binascii.Error, TypeError):
        return False
    return hmac.compare_digest(derived, public_key.strip())


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
