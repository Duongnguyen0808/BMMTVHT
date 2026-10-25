import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.models import FileRecord
from app.extensions import db


def tamper_demo(file_id=None):
    app = create_app()
    with app.app_context():
        print("==================================================")
        print("       SECURESHARE FILE TAMPERING DEMO TOOL       ")
        print("    (Chi su dung cho muc dich trinh dien an toan)  ")
        print("==================================================")

        if file_id is not None:
            record = db.session.get(FileRecord, file_id)
        else:
            # Pick first valid file
            record = FileRecord.query.filter_by(integrity_status='VALID').first()
            if not record:
                record = FileRecord.query.first()

        if not record:
            print("[-] Khong tim thay tep nao trong he thong de gia lap gia mao.")
            print("[*] Vui long chay: python scripts/seed_demo.py truoc.")
            return

        storage_folder = Path(app.config.get('STORAGE_FOLDER'))
        target_path = storage_folder / record.stored_name

        if not target_path.exists():
            print(f"[-] Khong tim thay tep vat ly tai: {target_path}")
            return

        # Read encrypted bytes and tamper
        original_bytes = target_path.read_bytes()

        # Simulate tampering: corrupt the last 32 bytes or flip bits in the ciphertext
        if len(original_bytes) > 20:
            # Modify bytes in middle/end
            tampered_bytes = bytearray(original_bytes)
            for i in range(10, min(25, len(tampered_bytes))):
                tampered_bytes[i] ^= 0xFF  # Invert bits
            tampered_bytes = bytes(tampered_bytes)
        else:
            tampered_bytes = b"CORRUPTED_TAMPERED_BYTES_DEMO_DATA_1234567890"

        target_path.write_bytes(tampered_bytes)

        print(f"[!] DA GIA LAP GIA MAO DU LIEU THANH CONG!")
        print(f"  - File ID: {record.id}")
        print(f"  - Ten goc: {record.original_name}")
        print(f"  - File ma hoa tren o dia: {record.stored_name}")
        print(f"  - SHA-256 ky vong (trong DB): {record.sha256_hash}")
        print("--------------------------------------------------")
        print("Kich ban kiem thu tiep theo:")
        print(f"  1. Dang nhap voi chu so huu hoac nguoi duoc chia se tep ID {record.id}")
        print(f"  2. Bam nut 'Tai xuong' tep '{record.original_name}'")
        print("  3. Ket qua mong doi:")
        print("     - He thong phat hien loi giai ma / khong khop SHA-256")
        print("     - Download bi CHAN (HTTP 400 / canh bao giao dien)")
        print("     - Trang thai toan ven doi thanh 'TAMPERED'")
        print("     - Audit log ghi nhan su kien: FILE_INTEGRITY_FAILED")
        print("  4. Dang nhap 'admin' de xem canh bao do trong Admin Dashboard & Logs.")
        print("--------------------------------------------------")
        print("[*] De phuc hoi he thong ve trang thai sach, chay lai:")
        print("    python scripts/seed_demo.py")
        print("==================================================")


if __name__ == '__main__':
    target_id = None
    if len(sys.argv) > 1:
        try:
            target_id = int(sys.argv[1])
        except ValueError:
            pass
    tamper_demo(target_id)
