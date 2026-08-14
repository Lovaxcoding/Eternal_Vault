import os
from flask import Flask, render_template
from dotenv import load_dotenv

# Charge les variables définies dans le fichier .env
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

    # Configuration recommandée pour le module EXIF (dossier d'upload & limite à 20 MB)
    # Modifier ce chemin pour cibler app/static/uploads
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

    # Assure que app/static/uploads existe
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Route d'atterrissage (Landing Page)
    @app.route('/')
    def landing():
        return render_template('landing.html')

    # Dashboard principal
    @app.route('/home')
    def home():
        return render_template('home.html')

    # Importation des Blueprints
    from app.modules.network.routes import network_bp
    from app.modules.geoip.routes import geoip_bp
    from app.modules.exif.routes import exif_bp

    # Enregistrement des Blueprints
    app.register_blueprint(network_bp)
    app.register_blueprint(geoip_bp)
    app.register_blueprint(exif_bp)

    return app