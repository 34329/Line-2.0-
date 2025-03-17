from time import sleep
import urllib
import shutil
import requests
while True:
    option = input("1.杀毒2.清理垃圾")
    if option == "1":
        print("准备杀毒")
        import os
        import hashlib
        
        malware_signatures_md5 = {
            "44d88612fea8a8f36de82e1278abb02f": "eicar_test_file",
            "eda588c0ee78b585f645aa42eff1e57a": "eicar_test_file_variant1",
            "19dbec50735b5f2a72d4199c4e184960": "eicar_test_file_variant2",
            "815b63b8bc28ae052029f8cbdd7098ce": "eicar_test_file_variant3",
            "c71091507f731c203b6c93bc91adedb6": "eicar_test_file_variant4",
            "0a456ffff1d3fd522457c187ebcf41e4": "eicar_test_file_variant5",
            "1aa4c64363b68622c9426ce96c4186f2": "eicar_test_file_variant6",
            "d214c717a357fe3a455610b197c390aa": "eicar_test_file_variant7",
            "dffe6e34209cb19ebe720c457a06edd6": "eicar_test_file_variant8",
            "512301c535c88255c9a252fdf70b7a03": "eicar_test_file_variant9",
            "d4a05ada747a970bff6e8c2c59c9b5cd": "eicar_test_file_variant10",
            "ad41ec81ab55c17397d3d6039752b0fd": "eicar_test_file_variant11",
            "a57db79f11a8c58d27f706bc1fe94e25": "eicar_test_file_variant12",
            "fc14eaf932b76c51ebf490105ba843eb": "eicar_test_file_variant13",
            "2a92da4b5a353ca41de980a49b329e7d": "eicar_test_file_variant14",
            "68abd642c33f3d62b7f0f92e20b266aa": "eicar_test_file_variant15",
            "ff5e1f27193ce51eec318714ef038bef": "eicar_test_file_variant16",
            "4c36884f0644946344fa847756f4a04e": "eicar_test_file_variant17",
            "2391109c40ccb0f982b86af86cfbc900": "eicar_test_file_variant18",
            "915178156c8caa25b548484c97dd19c1": "eicar_test_file_variant19",
            "dac5f1e894b500e6e467ae5d43b7ae3e": "eicar_test_file_variant20",
            "84c82835a5d21bbcf75a61706d8ab549": "eicar_test_file_variant21",
            "db349b97c37d22f5ea1d1841e3c89eb4": "eicar_test_file_variant22",
            "1de73f49db23cf5cc6e06f47767f7fda": "eicar_test_file_variant23",
            "71b6a493388e7d0b40c83ce903bc6b04": "eicar_test_file_variant24",
            "106b537598bce8003d787f4c47e6ecb9": "eicar_test_file_variant25",
    }
        
        malware_signatures_sha256 = {
            "eicar_test_file": "275a021bbfb648ebfab0f49d40a5f99163e921b2089f0aabf377bab4a8ab6a9e",  # EICAR测试文件的SHA-256哈希
        }
        
        def calculate_hash(file_path, algorithm='md5'):
            """计算文件的哈希值"""
            if algorithm == 'md5':
                hash_func = hashlib.md5()
            elif algorithm == 'sha256':
                hash_func = hashlib.sha256()
            else:
                raise ValueError("Unsupported hash algorithm")
        
            try:
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_func.update(chunk)
                return hash_func.hexdigest()
            except Exception as e:
                print(f"无法读取文件 {file_path}: {e}")
                return None
        
        def scan_directory(directory, algorithm='md5'):
            """扫描目录中的文件并检查是否包含已知恶意软件签名"""
            if algorithm == 'md5':
                signatures = malware_signatures_md5
            elif algorithm == 'sha256':
                signatures = malware_signatures_sha256
            else:
                raise ValueError("Unsupported hash algorithm")
        
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_hash = calculate_hash(file_path, algorithm)
                    if file_hash:
                        if file_hash in signatures.values():
                            print(f"发现恶意软件: {file_path} ({algorithm.upper()}: {file_hash})")
                        else:
                            print(f"文件安全: {file_path} ({algorithm.upper()}: {file_hash})")
        
        if __name__ == "__main__":
            directory_to_scan = input("请输入要扫描的目录路径: ")
            hash_algorithm = input("请选择哈希算法(md5/sha256,默认md5):").lower() or 'md5'
            if os.path.isdir(directory_to_scan):
                scan_directory(directory_to_scan, hash_algorithm)
            else:
                print("无效的目录路径")
        
    