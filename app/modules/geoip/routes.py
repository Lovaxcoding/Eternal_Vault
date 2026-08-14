from flask import Blueprint, render_template, request, jsonify
from app.modules.geoip.utils import get_geoip_data

geoip_bp = Blueprint('geoip', __name__)

@geoip_bp.route('/geoip', methods=['GET', 'POST'])
def mapper():
    if request.method == 'POST':
        data = request.get_json() or {}
        ip_target = data.get('ip', '').strip()
        
        # Si le champ est vide, utiliser l'IP de l'utilisateur
        if not ip_target:
            ip_target = request.headers.get('X-Forwarded-For', request.remote_addr or '')
            if ip_target:
                ip_target = ip_target.split(',')[0].strip()

        result = get_geoip_data(ip_target)
        return jsonify(result)

    return render_template('geoip/mapper.html')