from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import os

from argon2.low_level import (
    hash_secret_raw,
    Type,
)

from cryptography.exceptions import (
    InvalidTag,
)

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)

from core.fak_format import (
    SALT_SIZE,
    NONCE_SIZE,
    build_fak1_header,
    read_fak1_header,
    FAKError,
)

from core.file_utils import (
    validate_file,
    same_file,
    calculate_key_fingerprint,
    find_keyfile_by_fingerprint,
    find_keyfile_for_fak,
    get_encrypted_output_path,
    get_decrypted_output_path,
    ensure_parent_directory,
)


# ============================================================
# FAK1 密码学参数
#
# 这些参数必须保持不变。
#
# 如果修改：
#
#   ARGON2_TIME_COST
#   ARGON2_MEMORY_COST
#   ARGON2_PARALLELISM
#   AES_KEY_SIZE
#
# 旧版 FAK1 文件将无法正常解密。
# ============================================================

ARGON2_TIME_COST = 3

# 单位：KiB
# 65536 KiB = 64 MiB
ARGON2_MEMORY_COST = 65536

ARGON2_PARALLELISM = 4

# AES-256
AES_KEY_SIZE = 32


# ============================================================
# Callback
# ============================================================

StatusCallback = Callable[[str], None] | None


# ============================================================
# Exception
# ============================================================

class CryptoError(Exception):
    """
    加密 / 解密相关异常基础类。
    """


class EncryptionError(CryptoError):
    """
    文件加密失败。
    """


class DecryptionError(CryptoError):
    """
    文件解密失败。
    """


class KeyFileError(CryptoError):
    """
    Key 文件存在问题。
    """


class KeyFileNotFoundError(KeyFileError):
    """
    找不到 FAK 文件对应的 Key。
    """


class KeyFingerprintMismatchError(KeyFileError):
    """
    用户指定的 Key 与 FAK Header 中的 Fingerprint 不一致。
    """


class OutputFileExistsError(CryptoError):
    """
    输出文件已经存在。
    """


class AuthenticationError(DecryptionError):
    """
    AES-GCM Authentication Tag 验证失败。

    通常意味着：

    - Key 错误
    - 文件被修改
    - FAK 文件损坏
    """


# ============================================================
# Result
# ============================================================

@dataclass(frozen=True)
class EncryptionResult:
    """
    加密成功后的结果。
    """

    input_file: Path
    key_file: Path
    output_file: Path
    key_fingerprint: bytes


@dataclass(frozen=True)
class DecryptionResult:
    """
    解密成功后的结果。
    """

    input_file: Path
    key_file: Path
    output_file: Path
    original_filename: str
    key_fingerprint: bytes


# ============================================================
# Status
# ============================================================

def _report_status(
    callback: StatusCallback,
    message: str
) -> None:
    """
    向调用者报告当前处理状态。

    core 本身不关心这些文字最终显示在：
    - GUI Label
    - Status Bar
    - Log
    - CLI

    中的哪一个位置。
    """

    if callback is not None:
        callback(message)


# ============================================================
# Argon2id
# ============================================================

def derive_key(
    keyfile_bytes: bytes,
    salt: bytes
) -> bytes:
    """
    使用 FAK1 原始参数，通过 Argon2id 派生 AES-256 Key。

    与旧版本代码完全一致：

        secret      = Key 文件全部内容
        salt        = 16-byte random Salt
        time_cost   = 3
        memory_cost = 65536
        parallelism = 4
        hash_len    = 32
        type        = Argon2id

    Returns:
        32-byte AES Key
    """

    if not isinstance(
        keyfile_bytes,
        bytes
    ):
        raise TypeError(
            "keyfile_bytes 必须为 bytes"
        )

    if not keyfile_bytes:
        raise KeyFileError(
            "Key 文件为空"
        )

    if not isinstance(
        salt,
        bytes
    ):
        raise TypeError(
            "salt 必须为 bytes"
        )

    if len(salt) != SALT_SIZE:
        raise ValueError(
            f"Salt 长度必须为 {SALT_SIZE} bytes"
        )

    return hash_secret_raw(
        secret=keyfile_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=AES_KEY_SIZE,
        type=Type.ID
    )


# ============================================================
# Key File
# ============================================================

def read_key_file(
    key_file: str | Path
) -> bytes:
    """
    读取完整 Key 文件。

    注意：

    SHA-256 可以流式处理。

    但是 Argon2id 的 secret 参数必须传入完整 bytes，
    因此 Key 文件本身仍然需要加载到内存。

    一般建议 Key 文件使用较小文件。
    """

    path = validate_file(
        key_file
    )

    try:
        data = path.read_bytes()

    except OSError as exc:
        raise KeyFileError(
            f"无法读取 Key 文件：{path}"
        ) from exc

    if not data:
        raise KeyFileError(
            "Key 文件为空"
        )

    return data


# ============================================================
# 加密
# ============================================================

def encrypt_file(
    payload_file: str | Path,
    key_file: str | Path,
    output_file: str | Path | None = None,
    *,
    overwrite: bool = False,
    status_callback: StatusCallback = None,
) -> EncryptionResult:
    """
    使用 FAK1 格式加密文件。

    Args:
        payload_file:
            需要加密的原始文件。

        key_file:
            用于派生 AES Key 的 Key 文件。

        output_file:
            自定义输出位置。

            如果省略：

                document.pdf
                    ->
                document.pdf.fak

        overwrite:
            False:
                如果目标已存在，抛出 OutputFileExistsError。

            True:
                覆盖已有文件。

        status_callback:
            可选状态回调，例如：

                lambda message:
                    worker.status.emit(message)

    Returns:
        EncryptionResult

    注意：
        FAK1 使用 cryptography.AESGCM 高级 API。

        因此 Payload 当前仍需要完整加载到内存。
        真正的大文件流式加密需要未来设计 FAK2。
    """

    # --------------------------------------------------------
    # 文件检查
    # --------------------------------------------------------

    payload_path = validate_file(
        payload_file
    )

    key_path = validate_file(
        key_file
    )

    if same_file(
        payload_path,
        key_path
    ):
        raise KeyFileError(
            "Key 文件不能与需要加密的文件相同"
        )

    # --------------------------------------------------------
    # 输出位置
    # --------------------------------------------------------

    if output_file is None:
        output_path = (
            get_encrypted_output_path(
                payload_path
            )
        )

    else:
        output_path = Path(
            output_file
        ).expanduser()

    ensure_parent_directory(
        output_path
    )

    # 不允许把输出覆盖到输入文件本身
    if same_file(
        payload_path,
        output_path
    ):
        raise EncryptionError(
            "加密输出文件不能与原始文件相同"
        )

    if output_path.exists() and not overwrite:
        raise OutputFileExistsError(
            f"输出文件已经存在：{output_path}"
        )

    # --------------------------------------------------------
    # Fingerprint
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在计算 Key 指纹..."
    )

    try:
        key_fingerprint = (
            calculate_key_fingerprint(
                key_path
            )
        )

    except Exception as exc:
        raise KeyFileError(
            "计算 Key 指纹失败"
        ) from exc

    # --------------------------------------------------------
    # Key 文件
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在读取 Key 文件..."
    )

    key_data = read_key_file(
        key_path
    )

    # --------------------------------------------------------
    # 随机 Salt / Nonce
    # --------------------------------------------------------

    salt = os.urandom(
        SALT_SIZE
    )

    nonce = os.urandom(
        NONCE_SIZE
    )

    # --------------------------------------------------------
    # Argon2id
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在派生加密密钥..."
    )

    try:
        aes_key = derive_key(
            key_data,
            salt
        )

    except Exception as exc:
        raise EncryptionError(
            "密钥派生失败"
        ) from exc

    # --------------------------------------------------------
    # Payload
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在读取需要加密的文件..."
    )

    try:
        payload_data = (
            payload_path.read_bytes()
        )

    except OSError as exc:
        raise EncryptionError(
            f"无法读取需要加密的文件："
            f"{payload_path}"
        ) from exc

    # --------------------------------------------------------
    # AES-GCM
    #
    # 注意：
    #
    # 必须继续使用：
    #
    #     associated_data=None
    #
    # 否则会破坏 FAK1 格式兼容性。
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在加密文件..."
    )

    try:
        aes = AESGCM(
            aes_key
        )

        ciphertext = aes.encrypt(
            nonce,
            payload_data,
            None
        )

    except Exception as exc:
        raise EncryptionError(
            "AES-GCM 加密失败"
        ) from exc

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在生成 FAK 文件..."
    )

    try:
        header = build_fak1_header(
            salt=salt,
            nonce=nonce,
            key_fingerprint=key_fingerprint,
            filename=payload_path.name
        )

    except Exception as exc:
        raise EncryptionError(
            "无法生成 FAK Header"
        ) from exc

    # --------------------------------------------------------
    # 写入文件
    # --------------------------------------------------------

    try:
        with output_path.open(
            "wb"
        ) as f:

            f.write(
                header
            )

            f.write(
                ciphertext
            )

    except OSError as exc:
        raise EncryptionError(
            f"无法写入输出文件："
            f"{output_path}"
        ) from exc

    _report_status(
        status_callback,
        "加密完成"
    )

    return EncryptionResult(
        input_file=payload_path,
        key_file=key_path,
        output_file=output_path,
        key_fingerprint=key_fingerprint
    )


# ============================================================
# 解密时寻找 Key
# ============================================================

def resolve_key_file(
    fak_file: str | Path,
    target_fingerprint: bytes,
    *,
    key_file: str | Path | None = None,
    search_directory: str | Path | None = None,
    status_callback: StatusCallback = None,
) -> Path:
    """
    找到用于当前 FAK 文件的 Key。

    搜索优先级：

    1. 如果明确传入 key_file：
       直接验证这个 Key。

    2. 如果传入 search_directory：
       在指定目录搜索。

    3. 否则：
       自动在 .fak 文件所在目录搜索。

    这样 GUI 后面可以同时支持：

        自动寻找 Key

    和：

        找不到时手动选择 Key
    """

    fak_path = validate_file(
        fak_file
    )

    # --------------------------------------------------------
    # 用户明确指定 Key
    # --------------------------------------------------------

    if key_file is not None:

        _report_status(
            status_callback,
            "正在验证指定的 Key 文件..."
        )

        key_path = validate_file(
            key_file
        )

        fingerprint = (
            calculate_key_fingerprint(
                key_path
            )
        )

        if (
            fingerprint
            != target_fingerprint
        ):
            raise KeyFingerprintMismatchError(
                "选择的 Key 文件与该 FAK 文件不匹配"
            )

        return key_path

    # --------------------------------------------------------
    # 自动搜索
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在自动寻找 Key 文件..."
    )

    if search_directory is not None:

        key_path = (
            find_keyfile_by_fingerprint(
                directory=search_directory,
                target_fingerprint=target_fingerprint,
                exclude_files=[
                    fak_path
                ]
            )
        )

    else:

        key_path = (
            find_keyfile_for_fak(
                fak_file=fak_path,
                target_fingerprint=target_fingerprint
            )
        )

    if key_path is None:
        raise KeyFileNotFoundError(
            "未找到与该 FAK 文件匹配的 Key 文件"
        )

    return key_path


# ============================================================
# 解密
# ============================================================

def decrypt_file(
    fak_file: str | Path,
    key_file: str | Path | None = None,
    output_file: str | Path | None = None,
    *,
    search_directory: str | Path | None = None,
    overwrite: bool = False,
    status_callback: StatusCallback = None,
) -> DecryptionResult:
    """
    解密 FAK1 文件。

    默认行为：

        report.pdf.fak
        key.jpg

    两者在同一目录时：

        1. 读取 FAK Header
        2. 获取 Fingerprint
        3. 自动搜索匹配 Key
        4. Argon2id 派生 AES Key
        5. AES-GCM 解密
        6. 恢复 Header 中保存的原文件名

    Args:
        fak_file:
            FAK1 文件。

        key_file:
            可选。

            如果提供，则直接使用并验证 Fingerprint。

            如果没有提供，则自动搜索。

        output_file:
            自定义输出位置。

            默认使用 Header 保存的原始文件名。

        search_directory:
            可选 Key 搜索目录。

            默认搜索 FAK 文件所在目录。

        overwrite:
            是否允许覆盖已经存在的输出文件。

        status_callback:
            状态回调。

    Returns:
        DecryptionResult
    """

    fak_path = validate_file(
        fak_file
    )

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在读取 FAK 文件信息..."
    )

    try:
        header = read_fak1_header(
            fak_path
        )

    except FAKError:
        raise

    except Exception as exc:
        raise DecryptionError(
            "无法解析 FAK 文件"
        ) from exc

    # --------------------------------------------------------
    # Key
    # --------------------------------------------------------

    key_path = resolve_key_file(
        fak_file=fak_path,
        target_fingerprint=header.key_fingerprint,
        key_file=key_file,
        search_directory=search_directory,
        status_callback=status_callback
    )

    # 再次验证 Fingerprint
    #
    # resolve_key_file 已经会验证手动 Key，
    # 自动搜索本身也是通过 Fingerprint 找到的。
    #
    # 这里再次检查属于防御性验证。
    actual_fingerprint = (
        calculate_key_fingerprint(
            key_path
        )
    )

    if (
        actual_fingerprint
        != header.key_fingerprint
    ):
        raise KeyFingerprintMismatchError(
            "Key 文件指纹验证失败"
        )

    _report_status(
        status_callback,
        "Key 文件验证通过"
    )

    # --------------------------------------------------------
    # Key Data
    # --------------------------------------------------------

    key_data = read_key_file(
        key_path
    )

    # --------------------------------------------------------
    # Argon2id
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在派生解密密钥..."
    )

    try:
        aes_key = derive_key(
            key_data,
            header.salt
        )

    except Exception as exc:
        raise DecryptionError(
            "密钥派生失败"
        ) from exc

    # --------------------------------------------------------
    # Ciphertext
    #
    # 这里只读取 Ciphertext，不重复加载 Header。
    #
    # 但由于 AESGCM.decrypt() 的限制，
    # Ciphertext 仍然需要完整加载到 RAM。
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在读取加密数据..."
    )

    try:
        with fak_path.open(
            "rb"
        ) as f:

            f.seek(
                header.ciphertext_offset
            )

            ciphertext = f.read()

    except OSError as exc:
        raise DecryptionError(
            "无法读取 FAK 加密数据"
        ) from exc

    # --------------------------------------------------------
    # AES-GCM
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在解密文件..."
    )

    try:
        aes = AESGCM(
            aes_key
        )

        plaintext = aes.decrypt(
            header.nonce,
            ciphertext,
            None
        )

    except InvalidTag as exc:
        raise AuthenticationError(
            "解密验证失败。"
            "Key 文件可能不正确，"
            "或者 FAK 文件已经损坏。"
        ) from exc

    except Exception as exc:
        raise DecryptionError(
            "AES-GCM 解密失败"
        ) from exc

    # --------------------------------------------------------
    # Output Path
    # --------------------------------------------------------

    if output_file is None:

        output_path = (
            get_decrypted_output_path(
                fak_file=fak_path,
                original_filename=header.filename
            )
        )

    else:

        output_path = Path(
            output_file
        ).expanduser()

    ensure_parent_directory(
        output_path
    )

    # 防止意外覆盖 FAK 本身
    if same_file(
        fak_path,
        output_path
    ):
        raise DecryptionError(
            "解密输出文件不能覆盖 FAK 文件本身"
        )

    if output_path.exists() and not overwrite:
        raise OutputFileExistsError(
            f"输出文件已经存在：{output_path}"
        )

    # --------------------------------------------------------
    # Write Plaintext
    # --------------------------------------------------------

    _report_status(
        status_callback,
        "正在写入解密文件..."
    )

    try:
        output_path.write_bytes(
            plaintext
        )

    except OSError as exc:
        raise DecryptionError(
            f"无法写入解密文件："
            f"{output_path}"
        ) from exc

    _report_status(
        status_callback,
        "解密完成"
    )

    return DecryptionResult(
        input_file=fak_path,
        key_file=key_path,
        output_file=output_path,
        original_filename=header.filename,
        key_fingerprint=header.key_fingerprint
    )