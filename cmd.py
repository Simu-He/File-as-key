from pathlib import Path
import os
import struct
import hashlib

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# 常量
# ============================================================

FAK_MAGIC = b"FAK1"
FAK_VERSION = 1

SALT_SIZE = 16
NONCE_SIZE = 12
FINGERPRINT_SIZE = 8

SHA256_CHUNK_SIZE = 1024 * 1024  # 1 MiB


# ============================================================
# 密钥相关
# ============================================================

def derive_key(keyfile_bytes, salt):
    """
    使用 Key 文件内容 + Salt，通过 Argon2id 派生 256-bit AES Key。

    注意：
    这些参数必须保持不变，否则无法解密旧版 FAK 文件。
    """
    return hash_secret_raw(
        secret=keyfile_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )


def calculate_file_sha256(file_path):
    """
    流式计算文件 SHA-256。

    不使用 read_bytes() 一次性加载整个文件，
    因此即使文件很大，也只会占用少量内存。
    """
    sha256 = hashlib.sha256()

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(SHA256_CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.digest()


def calculate_key_fingerprint(key_file):
    """
    计算 Key 文件指纹。

    为兼容旧版 FAK：
    SHA256(Key文件内容) 的前 8 字节。
    """
    return calculate_file_sha256(key_file)[:FINGERPRINT_SIZE]


# ============================================================
# 文件扫描 / 选择
# ============================================================

def scan_files():
    """
    扫描当前目录中的普通文件。
    """
    files = [
        f for f in Path(".").iterdir()
        if f.is_file()
    ]

    files.sort(key=lambda x: x.name.lower())

    return files


def select_file(files, prompt):
    """
    让用户根据序号选择文件。
    """
    while True:
        try:
            idx = int(input(prompt))

            if 1 <= idx <= len(files):
                return files[idx - 1]

            print("序号超出范围")

        except ValueError:
            print("请输入数字")


def find_keyfile_by_fingerprint(all_files, target_fingerprint):
    """
    在当前目录自动寻找与目标 Fingerprint 匹配的 Key 文件。

    SHA-256 使用流式读取，避免候选文件过大时占用大量内存。
    """

    for file_path in all_files:

        if not file_path.is_file():
            continue

        try:
            fingerprint = calculate_key_fingerprint(file_path)

            if fingerprint == target_fingerprint:
                return file_path

        except (OSError, PermissionError):
            # 无法读取的文件直接跳过
            continue

    return None


# ============================================================
# 加密
# ============================================================

def encrypt_file(payload_file, key_file):
    """
    使用 Key 文件加密目标文件，并生成 .fak 文件。

    FAK 格式保持与旧版本完全一致：

    Magic              4 bytes   FAK1
    Version            1 byte    0x01
    Salt               16 bytes
    Nonce              12 bytes
    Key Fingerprint    8 bytes
    Filename Length    2 bytes   Big Endian
    Filename           N bytes   UTF-8
    Ciphertext         剩余数据
    """

    try:
        print("\n开始加密...")

        # ----------------------------------------------------
        # 读取 Key
        # ----------------------------------------------------

        key_data = key_file.read_bytes()

        # Fingerprint 使用流式 SHA256
        key_fingerprint = calculate_key_fingerprint(key_file)

        # ----------------------------------------------------
        # 随机参数
        # ----------------------------------------------------

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        # ----------------------------------------------------
        # 派生 AES Key
        # ----------------------------------------------------

        aes_key = derive_key(
            key_data,
            salt
        )

        # ----------------------------------------------------
        # 读取需要加密的文件
        #
        # AESGCM 高级接口需要一次性提供完整数据，
        # 所以这里只保留原来的 read_bytes() 行为。
        # ----------------------------------------------------

        payload_data = payload_file.read_bytes()

        # ----------------------------------------------------
        # AES-256-GCM 加密
        # ----------------------------------------------------

        aes = AESGCM(aes_key)

        ciphertext = aes.encrypt(
            nonce,
            payload_data,
            None
        )

        # ----------------------------------------------------
        # 保存原始文件名
        # ----------------------------------------------------

        filename_bytes = payload_file.name.encode("utf-8")

        if len(filename_bytes) > 65535:
            print("加密失败")
            print("文件名过长")
            return

        # ----------------------------------------------------
        # 构造 FAK
        # ----------------------------------------------------

        fak = bytearray()

        # Magic
        fak.extend(FAK_MAGIC)

        # Version
        fak.extend(
            bytes([FAK_VERSION])
        )

        # Salt
        fak.extend(salt)

        # Nonce
        fak.extend(nonce)

        # Key Fingerprint
        fak.extend(key_fingerprint)

        # Filename Length
        fak.extend(
            struct.pack(
                ">H",
                len(filename_bytes)
            )
        )

        # Filename
        fak.extend(filename_bytes)

        # Ciphertext
        fak.extend(ciphertext)

        # ----------------------------------------------------
        # 输出
        # ----------------------------------------------------

        output_file = payload_file.with_suffix(
            payload_file.suffix + ".fak"
        )

        output_file.write_bytes(fak)

        print("加密成功")
        print("输出文件:", output_file.name)
        print("Key 文件:", key_file.name)
        print("Key 指纹:", key_fingerprint.hex())

    except Exception as e:
        print("加密失败")
        print(e)


# ============================================================
# 解密
# ============================================================

def decrypt_file(payload_file):
    """
    解密 FAK 文件。

    会读取 FAK 内保存的 Key Fingerprint，
    然后自动扫描当前目录寻找对应 Key 文件。

    兼容以前生成的 FAK1 文件。
    """

    try:
        print("\n开始解密...")

        data = payload_file.read_bytes()

        # FAK 最小 Header：
        #
        # Magic       4
        # Version     1
        # Salt       16
        # Nonce      12
        # Fingerprint 8
        # Name Length 2
        #
        # 合计 43 bytes

        minimum_header_size = (
            4 +
            1 +
            SALT_SIZE +
            NONCE_SIZE +
            FINGERPRINT_SIZE +
            2
        )

        if len(data) < minimum_header_size:
            print("不是有效的 FAK 文件")
            print("文件长度过短")
            return

        offset = 0

        # ----------------------------------------------------
        # 1. Magic
        # ----------------------------------------------------

        magic = data[offset:offset + 4]
        offset += 4

        if magic != FAK_MAGIC:
            print("不是有效的 FAK 文件")
            return

        # ----------------------------------------------------
        # 2. Version
        # ----------------------------------------------------

        version = data[offset]
        offset += 1

        if version != FAK_VERSION:
            print("不支持的 FAK 版本:", version)
            return

        # ----------------------------------------------------
        # 3. Salt
        # ----------------------------------------------------

        salt = data[
            offset:
            offset + SALT_SIZE
        ]

        offset += SALT_SIZE

        # ----------------------------------------------------
        # 4. Nonce
        # ----------------------------------------------------

        nonce = data[
            offset:
            offset + NONCE_SIZE
        ]

        offset += NONCE_SIZE

        # ----------------------------------------------------
        # 5. Key Fingerprint
        # ----------------------------------------------------

        file_fingerprint = data[
            offset:
            offset + FINGERPRINT_SIZE
        ]

        offset += FINGERPRINT_SIZE

        # ----------------------------------------------------
        # 6. Filename Length
        # ----------------------------------------------------

        name_len = struct.unpack(
            ">H",
            data[offset:offset + 2]
        )[0]

        offset += 2

        # 检查文件名长度是否合法
        if offset + name_len > len(data):
            print("FAK 文件损坏")
            print("文件名长度异常")
            return

        # ----------------------------------------------------
        # 7. Filename
        # ----------------------------------------------------

        filename_bytes = data[
            offset:
            offset + name_len
        ]

        offset += name_len

        try:
            filename = filename_bytes.decode("utf-8")

        except UnicodeDecodeError:
            print("FAK 文件损坏")
            print("无法解析原始文件名")
            return

        # 防止异常路径
        if Path(filename).name != filename:
            print("FAK 文件中的原始文件名无效")
            return

        # ----------------------------------------------------
        # 8. Ciphertext
        # ----------------------------------------------------

        ciphertext = data[offset:]

        # AES-GCM 至少包含 16-byte authentication tag
        if len(ciphertext) < 16:
            print("FAK 文件损坏")
            print("加密数据长度异常")
            return

        # ----------------------------------------------------
        # 9. 自动搜索 Key
        # ----------------------------------------------------

        print("\n正在自动搜索 Key 文件...")

        all_files = list(
            Path(".").iterdir()
        )

        key_file = find_keyfile_by_fingerprint(
            all_files,
            file_fingerprint
        )

        if key_file is None:
            print("未找到匹配的 Key 文件")
            print(
                "需要的 Key 指纹:",
                file_fingerprint.hex()
            )
            return

        print(
            "找到 Key 文件:",
            key_file.name
        )

        # ----------------------------------------------------
        # 10. 验证 Fingerprint
        # ----------------------------------------------------

        actual_fingerprint = calculate_key_fingerprint(
            key_file
        )

        if actual_fingerprint != file_fingerprint:
            print("Key 文件不匹配")
            print("文件指纹不一致")
            return

        print("Key 文件验证通过")

        # ----------------------------------------------------
        # 11. 读取 Key 文件
        # ----------------------------------------------------

        key_data = key_file.read_bytes()

        # ----------------------------------------------------
        # 12. 派生 AES Key
        # ----------------------------------------------------

        aes_key = derive_key(
            key_data,
            salt
        )

        # ----------------------------------------------------
        # 13. AES-GCM 解密
        # ----------------------------------------------------

        aes = AESGCM(aes_key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        # ----------------------------------------------------
        # 14. 输出
        # ----------------------------------------------------

        output_file = payload_file.with_name(
            filename
        )

        if output_file.exists():

            print()
            print(
                f"警告：文件 {output_file.name} 已存在。"
            )

            answer = input(
                "是否覆盖？(y/N)："
            ).strip().lower()

            if answer not in ("y", "yes"):
                print("已取消写入")
                return

        output_file.write_bytes(
            plaintext
        )

        print("解密成功")
        print(
            "输出文件:",
            output_file.name
        )

    except Exception as e:
        print("解密失败")
        print(e)


# ============================================================
# UI
# ============================================================

def print_file_list(files):
    """
    显示当前目录文件列表。
    """

    print("\n当前目录文件：\n")

    for i, file in enumerate(
        files,
        start=1
    ):
        try:
            size = file.stat().st_size

        except OSError:
            size = 0

        print(
            f"[{i}] "
            f"{file.name} "
            f"({size} bytes)"
        )


# ============================================================
# Main
# ============================================================

def main():

    while True:

        print()
        print("=" * 40)
        print("FAK 文件加密工具")
        print("=" * 40)

        files = scan_files()

        if not files:
            print("当前目录没有文件")
            input("按回车返回...")
            continue

        print_file_list(files)

        print()
        print("[1] 加密文件")
        print("[2] 解密 FAK 文件")
        print("[0] 退出")
        print()

        mode = input(
            "请选择操作："
        ).strip()

        # ----------------------------------------------------
        # 退出
        # ----------------------------------------------------

        if mode == "0":

            print("程序已退出")
            break

        # ----------------------------------------------------
        # 输入检查
        # ----------------------------------------------------

        if mode not in ("1", "2"):

            print("无效选项")
            input(
                "按回车继续..."
            )

            continue

        print()

        # ----------------------------------------------------
        # 加密
        # ----------------------------------------------------

        if mode == "1":

            payload_file = select_file(
                files,
                "请选择需要加密的文件序号："
            )

            key_file = select_file(
                files,
                "请选择 Key 文件序号："
            )

            if payload_file == key_file:

                print(
                    "需要加密的文件与 Key 文件不能相同"
                )

                input(
                    "按回车继续..."
                )

                continue

            encrypt_file(
                payload_file,
                key_file
            )

        # ----------------------------------------------------
        # 解密
        # ----------------------------------------------------

        else:

            payload_file = select_file(
                files,
                "请选择需要解密的 FAK 文件序号："
            )

            decrypt_file(
                payload_file
            )

        print()
        input(
            "操作完成，按回车返回主菜单..."
        )


if __name__ == "__main__":
    main()