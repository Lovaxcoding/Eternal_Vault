import os
import uuid
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, jsonify, send_file, current_app, url_for
from app.modules.exif.utils import (
    clean_old_uploads,
    get_exif_metadata,
    generate_export_file
)

exif_bp = Blueprint('exif', __name__, url_prefix='/exif')

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.tiff', '.webp'}


@exif_bp.route('/')
def extractor_page():
    """Page d'accueil du module EXIF."""
    upload_folder = current_app.config.get('UPLOAD_FOLDER')
    clean_old_uploads(upload_folder)
    return render_template('exif/extract.html')


@exif_bp.route('/upload', methods=['POST'])
def handle_upload():
    """Gestion de l'upload et extraction des métadonnées."""
    upload_folder = current_app.config.get('UPLOAD_FOLDER')
    clean_old_uploads(upload_folder)

    if 'file' not in request.files:
        return jsonify({"success": False, "error": "Aucun fichier fourni."}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "Nom de fichier vide."}), 400

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"success": False, "error": "Format d'image non supporté."}), 400

    unique_filename = f"{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(upload_folder, unique_filename)
    file.save(filepath)

    # Récupère automatiquement la valeur chargée depuis le .env dans app.config
    api_key = current_app.config.get('EXIFTOOLS_API_KEY')

    # Extraction (API ExifTools ou fallback Pillow local si api_key est None)
    exif_data = get_exif_metadata(filepath, api_key=api_key)

    return jsonify({
        "success": True,
        "filename": unique_filename,
        "image_url": url_for('static', filename=f'uploads/{unique_filename}'),
        "data": exif_data
    })


@exif_bp.route('/export/<format_type>', methods=['POST'])
def export_data(format_type):
    """Téléchargement à la volée du rapport d'export."""
    data = request.json
    if not data:
        return jsonify({"error": "Données absentes."}), 400

    buffer, mimetype, download_name = generate_export_file(data, format_type)

    if not buffer:
        return jsonify({"error": "Format d'export non supporté."}), 400

    buffer.seek(0)
    return send_file(
        buffer,
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name
    )