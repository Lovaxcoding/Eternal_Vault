import os
import uuid
from flask import Blueprint, request, jsonify, render_template, current_app
from werkzeug.utils import secure_filename
from app.modules.logs.utils import analyze_log_file
from flask import send_file
from app.modules.logs.utils import generate_log_export_file


logs_bp = Blueprint('logs', __name__, url_prefix='/logs')

ALLOWED_LOG_EXTENSIONS = {'.log', '.txt'}


@logs_bp.route('/')
def logs_page():
    """Page d'accueil du module de Log Analysis."""
    return render_template('logs/index.html')


@logs_bp.route('/analyze', methods=['POST'])
def handle_log_upload():
    """Route d'upload et d'analyse de fichiers de logs."""
    upload_folder = current_app.config.get('UPLOAD_FOLDER')

    if 'file' not in request.files:
        return jsonify({"success": False, "error": "Aucun fichier fourni."}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "Nom de fichier vide."}), 400

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_LOG_EXTENSIONS:
        return jsonify({"success": False, "error": "Format non supporté (.log ou .txt requis)."}), 400

    unique_filename = f"log_{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(upload_folder, unique_filename)
    file.save(filepath)

    try:
        report = analyze_log_file(filepath)
        return jsonify({
            "success": True,
            "filename": filename,
            "analysis": report
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        # Nettoyage automatique du fichier temporaire après analyse
        if os.path.exists(filepath):
            os.remove(filepath)


@logs_bp.route('/export/<format_type>', methods=['POST'])
def export_log_report(format_type):
    """Téléchargement du rapport d'analyse de logs en HTML ou PDF."""
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "Données absentes."}), 400

    buffer, mimetype, download_name = generate_log_export_file(data, format_type)

    if not buffer:
        if format_type.lower() == 'pdf':
            return jsonify({
                "success": False,
                "error": "La conversion PDF nécessite la dépendance 'xhtml2pdf'."
            }), 400
        return jsonify({"success": False, "error": "Format d'export non supporté."}), 400

    buffer.seek(0)
    return send_file(
        buffer,
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name
    )