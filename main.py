from pathlib import Path
import os
import struct
import hashlib

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



def derive_key(keyfile_bytes, salt):
    return hash_secret_raw(
        secret=keyfile_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )



def scan_files():
    files = [
        f for f in Path(".").iterdir()
        if f.is_file()
    ]

    files.sort(key=lambda x: x.name.lower())

    return files


def select_file(files, prompt):
    while True:
        try:
            idx = int(input(prompt))

            if 1 <= idx <= len(files):
                return files[idx - 1]

            print("序号超出范围")

        except ValueError:
            print("请输入数字")



def find_keyfile_by_fingerprint(all_files, target_fp):
    """
    在当前目录自动寻找匹配的key文件
    """
    for f in all_files:
        if not f.is_file():
            continue

        data = f.read_bytes()
        fp = hashlib.sha256(data).digest()[:8]

        if fp == target_fp:
            return f

    return None




def compress_file(payload_file, key_file):

    try:

        print("\n开始加密...")

        payload_data = payload_file.read_bytes()
        key_data = key_file.read_bytes()

        # 文件指纹（未来自动寻找Key文件用）
        key_fingerprint = hashlib.sha256(key_data).digest()[:8]

        # 随机参数
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Argon2id派生AES密钥
        aes_key = derive_key(key_data, salt)

        # AES-GCM加密
        aes = AESGCM(aes_key)

        ciphertext = aes.encrypt(
            nonce,
            payload_data,
            None
        )

        filename_bytes = payload_file.name.encode("utf-8")

        # FAK格式
        fak = bytearray()

        # Magic
        fak.extend(b"FAK1")

        # Version
        fak.extend(b"\x01")

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

        output_file = payload_file.with_suffix(
            payload_file.suffix + ".fak"
        )

        output_file.write_bytes(fak)

        print("加密成功")
        print("输出文件:", output_file.name)
        print("文件指纹:", key_fingerprint.hex())

    except Exception as e:

        print("加密失败")
        print(e)





def decompress_file(payload_file, key_file=None):

    try:
        print("\n开始解密...")

        data = payload_file.read_bytes()
        offset = 0

        # -------- 1. Magic --------
        magic = data[offset:offset+4]
        offset += 4

        if magic != b"FAK1":
            print("不是有效的FAK文件")
            return

        # -------- 2. Version --------
        version = data[offset]
        offset += 1

        if version != 1:
            print("不支持的版本:", version)
            return

        # -------- 3. Salt --------
        salt = data[offset:offset+16]
        offset += 16

        # -------- 4. Nonce --------
        nonce = data[offset:offset+12]
        offset += 12

        # -------- 5. Key Fingerprint --------
        file_fingerprint = data[offset:offset+8]
        offset += 8

        # -------- 6. Filename --------
        name_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        filename = data[offset:offset+name_len].decode("utf-8")
        offset += name_len

        # -------- 7. Ciphertext --------
        ciphertext = data[offset:]


        # -------- 8. 自动寻找Key文件 --------

        print("\n正在自动搜索Key文件...")

        all_files = list(Path(".").iterdir())

        key_file = find_keyfile_by_fingerprint(all_files, file_fingerprint)

        if key_file is None:
            print("未找到匹配的Key文件")
            return

        print("找到Key文件:", key_file.name)

        key_data = key_file.read_bytes()



        # -------- 9. 验证指纹 --------
        actual_fingerprint = hashlib.sha256(key_data).digest()[:8]

        if actual_fingerprint != file_fingerprint:
            print("Key文件不匹配")
            print("文件指纹不一致")
            return

        print("Key文件验证通过")

        # -------- 10. 派生密钥 --------
        aes_key = hash_secret_raw(
            secret=key_data,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

        # -------- 11. 解密 --------
        aes = AESGCM(aes_key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        # -------- 12. 输出文件 --------
        output_file = payload_file.with_name(filename)

        output_file.write_bytes(plaintext)

        print("解密成功")
        print("输出文件:", output_file.name)

    except Exception as e:
        print("解密失败")
        print(e)








def main():

    while True:

        print("\n" + "=" * 40)
        print("FAK 文件加密工具")
        print("=" * 40)

        files = scan_files()

        if not files:
            print("当前目录没有文件")
            input("按回车返回...")
            continue

        print("\n当前目录文件：\n")

        for i, file in enumerate(files, start=1):
            size = file.stat().st_size
            print(f"[{i}] {file.name} ({size} bytes)")

        print()
        print("[1] 压缩")
        print("[2] 解压")
        print("[0] 退出")
        print()

        mode = input("请选择模式：").strip()

        if mode == "0":
            print("程序已退出")
            break

        if mode not in ("1", "2"):
            print("无效模式")
            input("按回车继续...")
            continue

        print()

        payload = select_file(
            files,
            "请选择文件本体序号："
        )

        if mode == "1": 
            keyfile = select_file( 
                files, 
                "请选择 Key 文件序号：" 
             )
            if payload == keyfile:
                print("文件本体与 Key 文件不能相同")
                input("按回车继续...")
                continue

        

        if mode == "1":
            compress_file(payload, keyfile)
        else:
            decompress_file(payload)

        print()
        input("操作完成，按回车返回主菜单...")



if __name__ == "__main__":
    main()