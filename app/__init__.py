from flask import Flask, render_template
from pathlib import Path
from app.config import Config
from app.extensions import db, login_manager, csrf, limiter
from app.models import User


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure storage folder exists
    storage_folder = Path(app.config.get('STORAGE_FOLDER', Path(__file__).resolve().parent.parent / 'storage'))
    storage_folder.mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Flask-Login user loader
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register Blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from app.files import bp as files_bp
    app.register_blueprint(files_bp)

    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    # Register Error Handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html', error=error), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html', error=error), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template('errors/413.html', error=error), 413

    @app.errorhandler(429)
    def ratelimit_handler(error):
        return render_template('errors/429.html', error=error), 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html', error=error), 500

    # Auto create tables if running in development or test
    with app.app_context():
        db.create_all()

    return app
