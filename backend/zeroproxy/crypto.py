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


def new_vless_uuid() -> str:
    """生成 VLESS UUID —— **随机**、与管理员口令无关。

    以前这里是 `derive_uuid(username, password)`(对"用户名:口令"做单轮 SHA-256):
    UUID 会随每一条 vless:// 订阅链接发到**每个客户端**手上, 而它是口令的单轮快速
    哈希 —— 任何拿到订阅的人都能按 SHA-256 速率离线爆破, PBKDF2 那 12 万次迭代
    等于白做 (口令下限还只有 6 位)。随机 UUID 照样持久化在 state.json 里,
    "重新生成配置时不变"这个诉求完全不受影响。
    """
    return str(_uuid.uuid4())


def derive_uuid(username: str, password: str) -> str:
    """[已废弃] 由口令确定性派生 UUID —— **不要再用**。

    保留函数只是为了老的单元测试/外部脚本还能 import; 面板初始化已经改用
    `new_vless_uuid()`。新代码若再调用它, 等于把管理员口令的快速哈希重新发出去。
    """
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


#: 口令哈希的当前参数 (PBKDF2-SHA256 迭代次数)。存储格式里**记录**了它, 所以以后
#: 调高时老哈希仍能验证 (按它自己那份参数), 不会把所有存量用户锁在门外。
PBKDF2_ITERATIONS = 120_000
PBKDF2_DIGEST = "sha256"


def hash_password(password: str, salt: bytes | None = None, iterations: int | None = None) -> str:
    """口令哈希, 格式 `pbkdf2$<iters>$<salt_hex>$<digest_hex>` (老格式 3 段也认)。

    为什么要把迭代次数写进串里: 以前是 `pbkdf2$<salt>$<digest>`, verify 永远用当前
    硬编码的 120000 重算 —— 一旦有人把次数调高或换算法, **所有存量口令立刻验证失败**,
    面板登录全挂 (只能靠 `z passwd` 绕过口令重置)。参数随哈希走才是可持续的写法。
    """
    rounds = int(iterations or PBKDF2_ITERATIONS)
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(PBKDF2_DIGEST, password.encode(), salt, rounds)
    return f"pbkdf2${rounds}${salt.hex()}${digest.hex()}"


def password_needs_rehash(stored: str) -> bool:
    """这条哈希是不是用更弱的参数算的 (登录成功后可以顺手重算)。"""
    parts = str(stored or "").split("$")
    if len(parts) < 3 or parts[0] != "pbkdf2":
        return True
    if len(parts) == 3:            # 老格式: 没有迭代次数
        return True
    try:
        return int(parts[1]) < PBKDF2_ITERATIONS
    except ValueError:
        return True


def verify_password(password: str, stored: str) -> bool:
    parts = str(stored or "").split("$")
    if len(parts) == 4 and parts[0] == "pbkdf2":
        try:
            rounds = int(parts[1])
        except ValueError:
            return False
        salt_hex, digest_hex = parts[2], parts[3]
    elif len(parts) == 3 and parts[0] == "pbkdf2":
        rounds, salt_hex, digest_hex = PBKDF2_ITERATIONS, parts[1], parts[2]
    else:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    # 比的是**摘要本身**, 不是整串: 整串比对会让老格式 (3 段) 永远失败, 因为
    # hash_password 现在输出 4 段 —— 那正好是"以后改参数就把所有人锁在外面"的同一个坑。
    actual = hashlib.pbkdf2_hmac(PBKDF2_DIGEST, password.encode(), salt, rounds)
    return hmac.compare_digest(actual, expected)
