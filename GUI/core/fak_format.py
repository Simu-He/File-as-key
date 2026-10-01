from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
import struct


# ============================================================
# FAK 格式常量
# ============================================================

FAK_MAGIC = b"FAK1"
FAK_VERSION = 1

MAGIC_SIZE = 4
VERSION_SIZE = 1

SALT_SIZE = 16
NONCE_SIZE = 12
FINGERPRINT_SIZE = 8

FILENAME_LENGTH_SIZE = 2

# AES-GCM Authentication Tag 长度
AES_GCM_TAG_SIZE = 16


# ============================================================
# FAK1 Header 固定部分长度
#
# Magic              4
# Version            1
# Salt              16
# Nonce             12
# Key Fingerprint    8
# Filename Length    2
#
# 合计：43 bytes
# ============================================================

FAK_FIXED_HEADER_SIZE = (
    MAGIC_SIZE
    + VERSION_SIZE
    + SALT_SIZE
    + NONCE_SIZE
    + FINGERPRINT_SIZE
    + FILENAME_LENGTH_SIZE
)


# ============================================================
# Exception
# ============================================================

class FAKError(Exception):
    """
    FAK 文件相关异常的基础类。
    """


class InvalidFAKFileError(FAKError):
    """
    文件不是有效的 FAK 文件，
    或文件结构已经损坏。
    """


class UnsupportedFAKVersionError(FAKError):
    """
    FAK Version 当前程序不支持。
    """


class InvalidFAKFilenameError(FAKError):
    """
    FAK Header 中保存的文件名无效。
    """


# ============================================================
# Header 数据结构
# ============================================================

@dataclass(frozen=True)
class FAKHeader:
    """
    FAK1 Header 解析结果。

    ciphertext_offset：
        Ciphertext 在整个 .fak 文件中的开始位置。

    header_size：
        当前 Header 的完整长度。
        对 FAK1 来说与 ciphertext_offset 相同。
    """

    magic: bytes

    version: int

    salt: bytes

    nonce: bytes

    key_fingerprint: bytes

    filename: str

    filename_bytes: bytes

    filename_length: int

    header_size: int

    ciphertext_offset: int


# ============================================================
# 基础工具
# ============================================================

def validate_filename(filename: str) -> None:
    """
    检查 FAK 中保存的原始文件名是否安全。

    FAK 只允许保存普通文件名：

        document.pdf

    不允许：

        ../document.pdf
        folder/document.pdf
        C:\\folder\\document.pdf

    防止解密时通过恶意 Header 写入其他目录。
    """

    if not filename:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名为空"
        )

    # Path.name 可以拦截当前系统使用的路径分隔符
    if Path(filename).name != filename:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名包含路径信息"
        )

    # Windows 风格路径在 Linux 上不一定会被 Path.name 识别，
    # 因此额外禁止两种路径分隔符。
    if "/" in filename or "\\" in filename:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名包含路径分隔符"
        )

    # 防止特殊目录名
    if filename in (".", ".."):
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名无效"
        )

    # 防止 NULL 字符
    if "\x00" in filename:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名包含非法字符"
        )


def encode_filename(filename: str) -> bytes:
    """
    将文件名编码为 UTF-8。

    FAK1 使用：
        2-byte Big Endian

    保存文件名字节长度。

    因此最大长度为：
        65535 bytes
    """

    validate_filename(filename)

    try:
        filename_bytes = filename.encode(
            "utf-8"
        )

    except UnicodeEncodeError as exc:
        raise InvalidFAKFilenameError(
            "原始文件名无法编码为 UTF-8"
        ) from exc

    if len(filename_bytes) > 0xFFFF:
        raise InvalidFAKFilenameError(
            "原始文件名过长"
        )

    return filename_bytes


def decode_filename(
    filename_bytes: bytes
) -> str:
    """
    将 FAK Header 中保存的 UTF-8 文件名解码。
    """

    try:
        filename = filename_bytes.decode(
            "utf-8"
        )

    except UnicodeDecodeError as exc:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名不是有效的 UTF-8"
        ) from exc

    validate_filename(filename)

    return filename


def read_exact(
    file_obj: BinaryIO,
    size: int,
    field_name: str
) -> bytes:
    """
    从二进制文件中精确读取指定长度。

    如果文件提前结束，则认为 FAK 文件损坏。
    """

    data = file_obj.read(size)

    if len(data) != size:
        raise InvalidFAKFileError(
            f"FAK 文件损坏：{field_name} 数据不完整"
        )

    return data


# ============================================================
# Header 构建
# ============================================================

def build_fak1_header(
    salt: bytes,
    nonce: bytes,
    key_fingerprint: bytes,
    filename: str
) -> bytes:
    """
    构建 FAK1 Header。

    文件格式严格保持与旧版程序一致：

    +----------------------+----------------------+
    | Field                | Size                 |
    +----------------------+----------------------+
    | Magic                | 4 bytes              |
    | Version              | 1 byte               |
    | Salt                 | 16 bytes             |
    | Nonce                | 12 bytes             |
    | Key Fingerprint      | 8 bytes              |
    | Filename Length      | 2 bytes (Big Endian) |
    | Filename             | N bytes UTF-8        |
    +----------------------+----------------------+

    Ciphertext 紧跟在 Header 后面。
    """

    if len(salt) != SALT_SIZE:
        raise ValueError(
            f"Salt 长度必须为 {SALT_SIZE} bytes"
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"Nonce 长度必须为 {NONCE_SIZE} bytes"
        )

    if len(key_fingerprint) != FINGERPRINT_SIZE:
        raise ValueError(
            "Key Fingerprint 长度必须为 "
            f"{FINGERPRINT_SIZE} bytes"
        )

    filename_bytes = encode_filename(
        filename
    )

    header = bytearray()

    # Magic
    header.extend(
        FAK_MAGIC
    )

    # Version
    header.append(
        FAK_VERSION
    )

    # Salt
    header.extend(
        salt
    )

    # Nonce
    header.extend(
        nonce
    )

    # Key Fingerprint
    header.extend(
        key_fingerprint
    )

    # Filename Length
    header.extend(
        struct.pack(
            ">H",
            len(filename_bytes)
        )
    )

    # Filename
    header.extend(
        filename_bytes
    )

    return bytes(header)


# ============================================================
# Bytes Header 解析
# ============================================================

def parse_fak1_header(
    data: bytes
) -> FAKHeader:
    """
    从 bytes 中解析 FAK1 Header。

    注意：
    data 可以是整个 FAK 文件，
    也可以是包含完整 Header 的 bytes。

    不需要包含完整 Ciphertext。
    """

    if len(data) < FAK_FIXED_HEADER_SIZE:
        raise InvalidFAKFileError(
            "FAK 文件长度过短"
        )

    offset = 0

    # --------------------------------------------------------
    # Magic
    # --------------------------------------------------------

    magic = data[
        offset:
        offset + MAGIC_SIZE
    ]

    offset += MAGIC_SIZE

    if magic != FAK_MAGIC:
        raise InvalidFAKFileError(
            "不是有效的 FAK 文件"
        )

    # --------------------------------------------------------
    # Version
    # --------------------------------------------------------

    version = data[offset]

    offset += VERSION_SIZE

    if version != FAK_VERSION:
        raise UnsupportedFAKVersionError(
            f"不支持的 FAK 版本：{version}"
        )

    # --------------------------------------------------------
    # Salt
    # --------------------------------------------------------

    salt = data[
        offset:
        offset + SALT_SIZE
    ]

    offset += SALT_SIZE

    # --------------------------------------------------------
    # Nonce
    # --------------------------------------------------------

    nonce = data[
        offset:
        offset + NONCE_SIZE
    ]

    offset += NONCE_SIZE

    # --------------------------------------------------------
    # Key Fingerprint
    # --------------------------------------------------------

    key_fingerprint = data[
        offset:
        offset + FINGERPRINT_SIZE
    ]

    offset += FINGERPRINT_SIZE

    # --------------------------------------------------------
    # Filename Length
    # --------------------------------------------------------

    filename_length_data = data[
        offset:
        offset + FILENAME_LENGTH_SIZE
    ]

    if len(filename_length_data) != FILENAME_LENGTH_SIZE:
        raise InvalidFAKFileError(
            "FAK 文件损坏：无法读取文件名长度"
        )

    filename_length = struct.unpack(
        ">H",
        filename_length_data
    )[0]

    offset += FILENAME_LENGTH_SIZE

    if filename_length == 0:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名为空"
        )

    # --------------------------------------------------------
    # Filename
    # --------------------------------------------------------

    filename_end = (
        offset
        + filename_length
    )

    if filename_end > len(data):
        raise InvalidFAKFileError(
            "FAK 文件损坏：文件名数据不完整"
        )

    filename_bytes = data[
        offset:
        filename_end
    ]

    filename = decode_filename(
        filename_bytes
    )

    offset = filename_end

    return FAKHeader(
        magic=magic,
        version=version,
        salt=salt,
        nonce=nonce,
        key_fingerprint=key_fingerprint,
        filename=filename,
        filename_bytes=filename_bytes,
        filename_length=filename_length,
        header_size=offset,
        ciphertext_offset=offset
    )


# ============================================================
# 流式 Header 解析
# ============================================================

def parse_fak1_header_from_file(
    file_obj: BinaryIO
) -> FAKHeader:
    """
    直接从已经打开的二进制文件中解析 FAK1 Header。

    与 parse_fak1_header() 相比，
    这个函数不会把整个 .fak 文件加载到内存。

    调用完成以后：

        file_obj.tell()

    会正好位于 Ciphertext 开始位置。

    这为未来 FAK2 / 流式处理做准备。
    """

    # --------------------------------------------------------
    # Magic
    # --------------------------------------------------------

    magic = read_exact(
        file_obj,
        MAGIC_SIZE,
        "Magic"
    )

    if magic != FAK_MAGIC:
        raise InvalidFAKFileError(
            "不是有效的 FAK 文件"
        )

    # --------------------------------------------------------
    # Version
    # --------------------------------------------------------

    version_data = read_exact(
        file_obj,
        VERSION_SIZE,
        "Version"
    )

    version = version_data[0]

    if version != FAK_VERSION:
        raise UnsupportedFAKVersionError(
            f"不支持的 FAK 版本：{version}"
        )

    # --------------------------------------------------------
    # Salt
    # --------------------------------------------------------

    salt = read_exact(
        file_obj,
        SALT_SIZE,
        "Salt"
    )

    # --------------------------------------------------------
    # Nonce
    # --------------------------------------------------------

    nonce = read_exact(
        file_obj,
        NONCE_SIZE,
        "Nonce"
    )

    # --------------------------------------------------------
    # Key Fingerprint
    # --------------------------------------------------------

    key_fingerprint = read_exact(
        file_obj,
        FINGERPRINT_SIZE,
        "Key Fingerprint"
    )

    # --------------------------------------------------------
    # Filename Length
    # --------------------------------------------------------

    filename_length_data = read_exact(
        file_obj,
        FILENAME_LENGTH_SIZE,
        "Filename Length"
    )

    filename_length = struct.unpack(
        ">H",
        filename_length_data
    )[0]

    if filename_length == 0:
        raise InvalidFAKFilenameError(
            "FAK 文件中的原始文件名为空"
        )

    # --------------------------------------------------------
    # Filename
    # --------------------------------------------------------

    filename_bytes = read_exact(
        file_obj,
        filename_length,
        "Filename"
    )

    filename = decode_filename(
        filename_bytes
    )

    # 当前流位置就是 Ciphertext Offset
    ciphertext_offset = file_obj.tell()

    return FAKHeader(
        magic=magic,
        version=version,
        salt=salt,
        nonce=nonce,
        key_fingerprint=key_fingerprint,
        filename=filename,
        filename_bytes=filename_bytes,
        filename_length=filename_length,
        header_size=ciphertext_offset,
        ciphertext_offset=ciphertext_offset
    )


# ============================================================
# 文件解析
# ============================================================

def read_fak1_header(
    file_path: Path | str
) -> FAKHeader:
    """
    从 .fak 文件中读取 Header。

    只读取 Header，
    不读取完整 Ciphertext。
    """

    path = Path(
        file_path
    )

    if not path.exists():
        raise FileNotFoundError(
            f"文件不存在：{path}"
        )

    if not path.is_file():
        raise InvalidFAKFileError(
            "目标不是普通文件"
        )

    try:
        with path.open(
            "rb"
        ) as f:

            header = (
                parse_fak1_header_from_file(
                    f
                )
            )

            # Ciphertext 至少应该包含 AES-GCM Tag。
            #
            # 不读取 Ciphertext，
            # 只通过文件大小判断。
            file_size = path.stat().st_size

            ciphertext_size = (
                file_size
                - header.ciphertext_offset
            )

            if ciphertext_size < AES_GCM_TAG_SIZE:
                raise InvalidFAKFileError(
                    "FAK 文件损坏："
                    "加密数据长度异常"
                )

            return header

    except OSError as exc:
        raise InvalidFAKFileError(
            f"无法读取 FAK 文件：{exc}"
        ) from exc


# ============================================================
# Version 检测
# ============================================================

def detect_fak_version(
    file_path: Path | str
) -> int:
    """
    快速读取 FAK 文件版本。

    这里只读取前 5 bytes：

        FAK1 + Version

    示例：

        version = detect_fak_version("test.pdf.fak")

    返回：
        1

    如果不是 FAK 文件则抛出异常。
    """

    path = Path(
        file_path
    )

    if not path.exists():
        raise FileNotFoundError(
            f"文件不存在：{path}"
        )

    if not path.is_file():
        raise InvalidFAKFileError(
            "目标不是普通文件"
        )

    try:
        with path.open(
            "rb"
        ) as f:

            prefix = f.read(
                MAGIC_SIZE
                + VERSION_SIZE
            )

    except OSError as exc:
        raise InvalidFAKFileError(
            f"无法读取文件：{exc}"
        ) from exc

    if len(prefix) < (
        MAGIC_SIZE
        + VERSION_SIZE
    ):
        raise InvalidFAKFileError(
            "文件长度过短"
        )

    magic = prefix[:MAGIC_SIZE]

    if magic != FAK_MAGIC:
        raise InvalidFAKFileError(
            "不是有效的 FAK 文件"
        )

    return prefix[MAGIC_SIZE]


# ============================================================
# 简单判断
# ============================================================

def is_fak_file(
    file_path: Path | str
) -> bool:
    """
    根据真实 Magic 判断文件是否为 FAK 文件。

    注意：
    不依赖 .fak 扩展名。

    即使文件名是：

        document.bin

    只要内部 Magic 是：

        FAK1

    仍然会返回 True。
    """

    path = Path(
        file_path
    )

    if not path.is_file():
        return False

    try:
        with path.open(
            "rb"
        ) as f:

            magic = f.read(
                MAGIC_SIZE
            )

        return magic == FAK_MAGIC

    except OSError:
        return False