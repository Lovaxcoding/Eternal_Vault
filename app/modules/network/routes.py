from flask import Blueprint, render_template

# Déclaration du Blueprint "network"
network_bp = Blueprint('network', __name__)

@network_bp.route('/calculator')
def calculator():
    # Affiche ton fichier HTML (ex: network/calculator.html ou ip_calc.html)
    return render_template('network/calculator.html')