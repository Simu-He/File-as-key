from pathlib import Path
from typing import Iterable
import hashlib

from core.fak_format import FINGERPRINT_SIZE


# ============================================================
# 常量
# ============================================================

# SHA-256 流式读取块大小
#
# 1 MiB：
# - 内存占用很低
# - 对大文件性能也足够好
#
# 修改这个值不会影响 SHA-256 结果，
# 因此不会影响旧 FAK 文件兼容性。
SHA256_CHUNK_SIZE = 1024 * 1024


# ============================================================
# Path 工具
# ============================================================

def normalize_path(
    file_path: str | Path
) -> Path:
    """
    将 str / Path 统一转换为 Path。

    不要求文件一定存在。
    """

    return Path(file_path).expanduser()


def validate_file(
    file_path: str | Path
) -> Path:
    """
    检查路径是否存在且为普通文件。

    返回标准 Path 对象。

    Raises:
        FileNotFoundError:
            文件不存在。

        ValueError:
            路径不是普通文件。
    """

    path = normalize_path(
        file_path
    )

    if not path.exists():
        raise FileNotFoundError(
            f"文件不存在：{path}"
        )

    if not path.is_file():
        raise ValueError(
            f"目标不是普通文件：{path}"
        )

    return path


def same_file(
    path1: str | Path,
    path2: str | Path
) -> bool:
    """
    判断两个路径是否指向同一个文件。

    优先使用 Path.samefile()。

    如果文件不存在或 samefile() 无法使用，
    则退回 resolve() 路径比较。
    """

    p1 = normalize_path(path1)
    p2 = normalize_path(path2)

    try:
        return p1.samefile(p2)

    except (OSError, FileNotFoundError):
        try:
            return (
                p1.resolve()
                ==
                p2.resolve()
            )

        except OSError:
            return (
                str(p1.absolute())
                ==
                str(p2.absolute())
            )


# ============================================================
# SHA-256
# ============================================================

def calculate_file_sha256(
    file_path: str | Path,
    chunk_size: int = SHA256_CHUNK_SIZE
) -> bytes:
    """
    流式计算整个文件的 SHA-256。

    不会使用：

        file.read_bytes()

    将整个文件一次性加载进内存。

    即使文件有几十 GB，
    内存中也只保留一个 chunk。

    Args:
        file_path:
            需要计算 SHA-256 的文件。

        chunk_size:
            每次读取大小。

    Returns:
        完整 32-byte SHA-256 Digest。
    """

    path = validate_file(
        file_path
    )

    if chunk_size <= 0:
        raise ValueError(
            "chunk_size 必须大于 0"
        )

    sha256 = hashlib.sha256()

    try:
        with path.open("rb") as f:

            while True:

                chunk = f.read(
                    chunk_size
                )

                if not chunk:
                    break

                sha256.update(
                    chunk
                )

    except OSError as exc:
        raise OSError(
            f"无法读取文件：{path}"
        ) from exc

    return sha256.digest()


def calculate_file_sha256_hex(
    file_path: str | Path,
    chunk_size: int = SHA256_CHUNK_SIZE
) -> str:
    """
    返回 SHA-256 的十六进制字符串。

    示例：

        a3b891...
    """

    return calculate_file_sha256(
        file_path,
        chunk_size
    ).hex()


# ============================================================
# Key Fingerprint
# ============================================================

def calculate_key_fingerprint(
    key_file: str | Path
) -> bytes:
    """
    计算 FAK1 Key Fingerprint。

    FAK1 规则：

        SHA256(Key 文件内容)[:8]

    即：

        SHA-256 前 64 bit

    注意：
    此算法必须保持不变，
    否则旧 FAK 文件将无法自动匹配 Key。
    """

    digest = calculate_file_sha256(
        key_file
    )

    return digest[
        :FINGERPRINT_SIZE
    ]


def calculate_key_fingerprint_hex(
    key_file: str | Path
) -> str:
    """
    返回适合显示的 Key Fingerprint Hex。

    示例：

        a32f89c21d77920a
    """

    return calculate_key_fingerprint(
        key_file
    ).hex()


def format_fingerprint(
    fingerprint: bytes | str
) -> str:
    """
    将 Fingerprint 格式化成适合 GUI 显示的形式。

    示例：

        A32F 89C2 1D77 920A
    """

    if isinstance(
        fingerprint,
        bytes
    ):
        value = fingerprint.hex()

    else:
        value = fingerprint

    value = (
        value
        .replace(" ", "")
        .strip()
        .upper()
    )

    return " ".join(
        value[i:i + 4]
        for i in range(
            0,
            len(value),
            4
        )
    )


# ============================================================
# 文件扫描
# ============================================================

def list_files(
    directory: str | Path
) -> list[Path]:
    """
    获取指定目录中的普通文件。

    只扫描当前目录，
    不递归进入子目录。

    按文件名排序。
    """

    directory = normalize_path(
        directory
    )

    if not directory.exists():
        raise FileNotFoundError(
            f"目录不存在：{directory}"
        )

    if not directory.is_dir():
        raise ValueError(
            f"目标不是目录：{directory}"
        )

    try:
        files = [
            path
            for path in directory.iterdir()
            if path.is_file()
        ]

    except OSError as exc:
        raise OSError(
            f"无法读取目录：{directory}"
        ) from exc

    files.sort(
        key=lambda path:
        path.name.lower()
    )

    return files


# ============================================================
# Key 自动搜索
# ============================================================

def find_keyfile_by_fingerprint(
    directory: str | Path,
    target_fingerprint: bytes,
    exclude_files: Iterable[str | Path] | None = None
) -> Path | None:
    """
    在指定目录中自动寻找与 FAK Fingerprint 匹配的 Key 文件。

    每个候选文件都使用流式 SHA-256，
    因此不会把大文件完整读入内存。

    Args:
        directory:
            搜索目录。

        target_fingerprint:
            FAK Header 中保存的 8-byte Fingerprint。

        exclude_files:
            不参与扫描的文件列表。

            例如解密时可以排除当前 .fak 文件：

                exclude_files=[payload_file]

    Returns:
        找到：
            Path

        未找到：
            None
    """

    if not isinstance(
        target_fingerprint,
        bytes
    ):
        raise TypeError(
            "target_fingerprint 必须为 bytes"
        )

    if len(
        target_fingerprint
    ) != FINGERPRINT_SIZE:
        raise ValueError(
            "Fingerprint 长度必须为 "
            f"{FINGERPRINT_SIZE} bytes"
        )

    files = list_files(
        directory
    )

    excluded: list[Path] = []

    if exclude_files is not None:

        for path in exclude_files:

            try:
                excluded.append(
                    normalize_path(path).resolve()
                )

            except OSError:
                excluded.append(
                    normalize_path(path)
                )

    for candidate in files:

        # ----------------------------------------------------
        # 排除指定文件
        # ----------------------------------------------------

        try:
            candidate_resolved = (
                candidate.resolve()
            )

        except OSError:
            candidate_resolved = candidate

        if candidate_resolved in excluded:
            continue

        # ----------------------------------------------------
        # Fingerprint
        # ----------------------------------------------------

        try:
            fingerprint = (
                calculate_key_fingerprint(
                    candidate
                )
            )

        except (
            OSError,
            PermissionError,
            FileNotFoundError
        ):
            # 无法读取的候选文件直接跳过
            continue

        if (
            fingerprint
            ==
            target_fingerprint
        ):
            return candidate

    return None


def find_keyfile_for_fak(
    fak_file: str | Path,
    target_fingerprint: bytes
) -> Path | None:
    """
    在 FAK 文件所在目录自动寻找 Key。

    这是 GUI / crypto 层最常使用的封装。

    例如：

        document.pdf.fak
        key.jpg

    两者位于：

        D:/files/

    那么程序会自动搜索：

        D:/files/

    而不是 Python 当前工作目录。

    当前 FAK 文件本身会自动排除。
    """

    fak_path = validate_file(
        fak_file
    )

    return find_keyfile_by_fingerprint(
        directory=fak_path.parent,
        target_fingerprint=target_fingerprint,
        exclude_files=[
            fak_path
        ]
    )


# ============================================================
# 文件大小
# ============================================================

def format_file_size(
    size: int
) -> str:
    """
    将字节数格式化为方便阅读的文件大小。

    示例：

        512
            -> 512 B

        1536
            -> 1.50 KB

        10485760
            -> 10.00 MB
    """

    if size < 0:
        raise ValueError(
            "文件大小不能小于 0"
        )

    units = (
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
        "PB",
    )

    value = float(size)

    for unit in units:

        if (
            value < 1024
            or
            unit == units[-1]
        ):

            if unit == "B":
                return (
                    f"{int(value)} {unit}"
                )

            return (
                f"{value:.2f} {unit}"
            )

        value /= 1024

    return f"{size} B"


def get_file_size(
    file_path: str | Path
) -> int:
    """
    获取文件大小（bytes）。
    """

    path = validate_file(
        file_path
    )

    try:
        return path.stat().st_size

    except OSError as exc:
        raise OSError(
            f"无法获取文件大小：{path}"
        ) from exc


# ============================================================
# 输出文件路径
# ============================================================

def get_encrypted_output_path(
    payload_file: str | Path
) -> Path:
    """
    根据原文件获得 FAK 输出路径。

    与旧程序行为完全一致。

    示例：

        document.pdf
            ->
        document.pdf.fak

        image.jpg
            ->
        image.jpg.fak
    """

    path = normalize_path(
        payload_file
    )

    return path.with_suffix(
        path.suffix + ".fak"
    )


def get_decrypted_output_path(
    fak_file: str | Path,
    original_filename: str
) -> Path:
    """
    获得解密输出路径。

    解密后的文件与 .fak 文件保存在同一目录。

    示例：

        D:/data/document.pdf.fak

    Header：
        document.pdf

    输出：

        D:/data/document.pdf
    """

    fak_path = normalize_path(
        fak_file
    )

    # fak_format.py 已经会验证 filename，
    # 这里再做一层简单保护。
    filename_path = Path(
        original_filename
    )

    if (
        not original_filename
        or
        filename_path.name
        != original_filename
        or
        "/" in original_filename
        or
        "\\" in original_filename
    ):
        raise ValueError(
            "原始文件名无效"
        )

    return fak_path.parent / original_filename


def get_available_output_path(
    output_path: str | Path
) -> Path:
    """
    如果目标文件不存在，直接返回。

    如果已经存在，则自动生成不冲突的文件名。

    示例：

        document.pdf
            已存在

        -> document (1).pdf

        document (1).pdf
            也存在

        -> document (2).pdf

    注意：
    是否使用该函数由上层决定。

    如果 GUI 希望询问用户是否覆盖，
    可以不调用这个函数。
    """

    path = normalize_path(
        output_path
    )

    if not path.exists():
        return path

    parent = path.parent

    suffixes = "".join(
        path.suffixes
    )

    if suffixes:
        base_name = path.name[
            :-len(suffixes)
        ]

    else:
        base_name = path.name

    index = 1

    while True:

        candidate = parent / (
            f"{base_name} ({index})"
            f"{suffixes}"
        )

        if not candidate.exists():
            return candidate

        index += 1


# ============================================================
# 输出目录检查
# ============================================================

def ensure_parent_directory(
    file_path: str | Path
) -> Path:
    """
    确保目标文件的父目录存在。

    当前项目一般不会主动创建复杂目录，
    但 crypto.py 写文件前可以调用此函数。
    """

    path = normalize_path(
        file_path
    )

    parent = path.parent

    if not parent.exists():
        raise FileNotFoundError(
            f"输出目录不存在：{parent}"
        )

    if not parent.is_dir():
        raise ValueError(
            f"输出目录无效：{parent}"
        )

    return path