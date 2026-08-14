from flask import Flask, render_template

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

    # Route d'atterrissage (Landing Page)
    @app.route('/')
    def landing():
        return render_template('landing.html')

    # Dashboard principal
    @app.route('/home')
    def home():
        return render_template('home.html')

    # Enregistrement des futurs Blueprints ici...
    # from app.modules.network.routes import network_bp
    # app.register_blueprint(network_bp, url_prefix='/network')
    # Import et enregistrement du Blueprint network
    from app.modules.network.routes import network_bp
    app.register_blueprint(network_bp, url_prefix='/network')

    return app