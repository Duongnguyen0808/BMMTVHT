"""
Script tạo tệp mẫu thử nghiệm Demo 7 (Ngụy trang tệp nhị phân độc hại)
Tạo tệp: sample_malware_disguised.pdf mang chữ ký nhị phân Windows PE 'MZ'
Dùng để tải lên hệ thống kiểm chứng tính năng chặn Deep Magic Bytes Inspection.
"""
from pathlib import Path

def create_demo_spoofed_file():
    target_path = Path("sample_malware_disguised.pdf")
    # Header Windows PE Executable 'MZ\x90\x00'
    fake_payload = b"MZ\x90\x00\x03\x00\x00\x00Demo Windows Executable Disguised as PDF for Cybersecurity Testing"
    with open(target_path, "wb") as f:
        f.write(fake_payload)
    print(f"[OK] Created spoofed test file: {target_path.absolute()}")

if __name__ == "__main__":
    create_demo_spoofed_file()
