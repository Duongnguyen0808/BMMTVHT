import secrets
from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / '.env'
ENV_EXAMPLE = BASE_DIR / '.env.example'


def generate_keys():
    new_fernet_key = Fernet.generate_key().decode('utf-8')
    new_secret_key = secrets.token_urlsafe(32)

    print("==================================================")
    print("        SECURESHARE KEY GENERATOR                 ")
    print("==================================================")
    print(f"[*] Generated FERNET_KEY : {new_fernet_key}")
    print(f"[*] Generated SECRET_KEY : {new_secret_key}")

    if not ENV_FILE.exists():
        if ENV_EXAMPLE.exists():
            content = ENV_EXAMPLE.read_text(encoding='utf-8')
        else:
            content = (
                "FLASK_ENV=development\n"
                "SECRET_KEY=change-me\n"
                "FERNET_KEY=generate-me\n"
                "DATABASE_URL=sqlite:///secureshare.db\n"
                "MAX_CONTENT_LENGTH=10485760\n"
                "SESSION_TIMEOUT_MINUTES=30\n"
            )
        ENV_FILE.write_text(content, encoding='utf-8')
        print(f"[+] Created '{ENV_FILE.name}' from template.")

    # Read existing .env lines
    lines = ENV_FILE.read_text(encoding='utf-8').splitlines()
    new_lines = []
    fernet_found = False
    secret_found = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("FERNET_KEY="):
            new_lines.append(f"FERNET_KEY={new_fernet_key}")
            fernet_found = True
        elif stripped.startswith("SECRET_KEY="):
            val = stripped.split("=", 1)[1].strip()
            if val in ('change-me', 'change-me-to-a-very-secure-random-key-for-flask', ''):
                new_lines.append(f"SECRET_KEY={new_secret_key}")
            else:
                new_lines.append(line)
            secret_found = True
        else:
            new_lines.append(line)

    if not fernet_found:
        new_lines.append(f"FERNET_KEY={new_fernet_key}")
    if not secret_found:
        new_lines.append(f"SECRET_KEY={new_secret_key}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding='utf-8')
    print(f"[+] Successfully updated '{ENV_FILE.name}' with new cryptographic keys!")
    print("==================================================")


if __name__ == '__main__':
    generate_keys()
