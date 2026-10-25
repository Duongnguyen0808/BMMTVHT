import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1').lower() in ('1', 'true')
    print(f"[*] Starting SecureShare on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
