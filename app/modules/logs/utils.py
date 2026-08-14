import re
from collections import Counter
import io
import json

# Import optionnel pour le support PDF
try:
    from xhtml2pdf import pisa
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False


# Regex pour les logs Nginx / Apache Combined Format
# Ex: 192.168.1.1 - - [15/Aug/2026:02:11:00 +0000] "GET /admin HTTP/1.1" 200 512 "ref" "User-Agent"
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)?\s*(?P<path>\S+)?\s*(?P<protocol>[^"]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Signatures simples de détection d'attaques
PATTERNS_SUSPECTS = {
    "sqli": re.compile(r"(union\s+select|select\s+.*\s+from|or\s+1=1|drop\s+table|sleep\(\d+\))", re.IGNORECASE),
    "path_traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|c:\\boot\.ini)", re.IGNORECASE),
    "xss": re.compile(r"(<script>|javascript:|onerror=|onload=)", re.IGNORECASE),
    "scanners": re.compile(r"(sqlmap|nikto|nmap|gobuster|dirbuster|wpscan)", re.IGNORECASE)
}


def parse_log_line(line):
    """Extrait les champs d'une ligne de log Web."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    
    data = match.groupdict()
    try:
        data['status'] = int(data['status'])
        data['bytes'] = int(data['bytes']) if data['bytes'].isdigit() else 0
    except ValueError:
        pass
        
    return data


def analyze_log_file(filepath):
    """Analyse complète du fichier de log."""
    total_requests = 0
    ip_counter = Counter()
    status_counter = Counter()
    user_agents = Counter()
    alerts = []
    
    # Suivi du rate-limiting / brute-force par IP
    ip_status_4xx = Counter()

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            parsed = parse_log_line(line)
            if not parsed:
                continue

            total_requests += 1
            ip = parsed['ip']
            path = parsed['path'] or ''
            ua = parsed['user_agent'] or ''
            status = parsed['status']

            ip_counter[ip] += 1
            status_counter[status] += 1
            user_agents[ua] += 1

            if status in [401, 403, 404]:
                ip_status_4xx[ip] += 1

            # 1. Détection de signatures d'attaques
            for attack_type, pattern in PATTERNS_SUSPECTS.items():
                if pattern.search(path) or pattern.search(ua):
                    alerts.append({
                        "line": line_num,
                        "type": attack_type.upper(),
                        "ip": ip,
                        "path": path,
                        "user_agent": ua,
                        "severity": "CRITICAL" if attack_type in ["sqli", "path_traversal"] else "WARNING"
                    })

    # 2. Détection de comportement anormal (ex: Force Brute / Déni de service)
    for ip, count_4xx in ip_status_4xx.items():
        if count_4xx > 50:
            alerts.append({
                "line": None,
                "type": "BRUTE_FORCE_OR_SCAN",
                "ip": ip,
                "details": f"{count_4xx} erreurs 4xx générées par cette IP.",
                "severity": "HIGH"
            })

    return {
        "summary": {
            "total_requests": total_requests,
            "unique_ips": len(ip_counter),
            "total_alerts": len(alerts)
        },
        "top_ips": dict(ip_counter.most_common(10)),
        "status_distribution": dict(status_counter),
        "top_user_agents": dict(user_agents.most_common(5)),
        "alerts": alerts
    }



def build_html_report(data):
    """Génère un rapport HTML complet et autonome avec CSS intégré."""
    summary = data.get('summary', {})
    top_ips = data.get('top_ips', {})
    status_dist = data.get('status_distribution', {})
    alerts = data.get('alerts', [])

    # HTML/CSS pour un rendu propre à l'écran et à l'impression / PDF
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'Analyse de Logs</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; background-color: #f8f9fa; }}
        .header {{ background-color: #1e293b; color: #ffffff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .cards {{ display: flex; gap: 15px; margin-bottom: 20px; }}
        .card {{ background: #ffffff; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0; flex: 1; text-align: center; }}
        .card .value {{ font-size: 22px; font-weight: bold; color: #0f172a; margin-top: 5px; }}
        h2 {{ color: #1e293b; border-bottom: 2px solid #cbd5e1; padding-bottom: 5px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; background: #ffffff; margin-bottom: 20px; border-radius: 6px; overflow: hidden; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
        th {{ background-color: #f1f5f9; color: #475569; font-weight: bold; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; display: inline-block; }}
        .badge-CRITICAL {{ background-color: #dc2626; }}
        .badge-HIGH {{ background-color: #ea580c; }}
        .badge-WARNING {{ background-color: #d97706; }}
    </style>
</head>
<body>

    <div class="header">
        <h1>🛡️ Rapport d'Analyse de Logs Web</h1>
        <p style="margin: 5px 0 0 0; font-size: 13px; opacity: 0.8;">Généré automatiquement par le module Log Analysis</p>
    </div>

    <div class="cards">
        <div class="card">
            <div>Total Requêtes</div>
            <div class="value">{summary.get('total_requests', 0)}</div>
        </div>
        <div class="card">
            <div>IP Unique(s)</div>
            <div class="value">{summary.get('unique_ips', 0)}</div>
        </div>
        <div class="card">
            <div>Alertes Sécurité</div>
            <div class="value" style="color: {'#dc2626' if summary.get('total_alerts', 0) > 0 else '#16a34a'};">
                {summary.get('total_alerts', 0)}
            </div>
        </div>
    </div>

    <h2>⚠️ Alertes et Comportements Suspects ({len(alerts)})</h2>
    <table>
        <thead>
            <tr>
                <th>Ligne</th>
                <th>Type</th>
                <th>Sévérité</th>
                <th>IP Source</th>
                <th>Cible / Détails</th>
            </tr>
        </thead>
        <tbody>
"""

    if not alerts:
        html_content += '<tr><td colspan="5" style="text-align:center; color:#16a34a;">Aucune anomalie détectée.</td></tr>'
    else:
        for alert in alerts:
            line_str = str(alert.get('line')) if alert.get('line') else 'N/A'
            sev = alert.get('severity', 'WARNING')
            details = alert.get('path') or alert.get('details') or ''
            html_content += f"""
            <tr>
                <td>{line_str}</td>
                <td><strong>{alert.get('type')}</strong></td>
                <td><span class="badge badge-{sev}">{sev}</span></td>
                <td><code>{alert.get('ip')}</code></td>
                <td><code>{details}</code></td>
            </tr>"""

    html_content += """
        </tbody>
    </table>

    <h2>🌐 Top 10 des Adresses IP</h2>
    <table>
        <thead>
            <tr><th>Adresse IP</th><th>Nombre de requêtes</th></tr>
        </thead>
        <tbody>"""
    for ip, count in top_ips.items():
        html_content += f"<tr><td><code>{ip}</code></td><td>{count}</td></tr>"

    html_content += """
        </tbody>
    </table>

    <h2>📊 Répartition par Code d'État HTTP</h2>
    <table>
        <thead>
            <tr><th>Code HTTP</th><th>Occurrences</th></tr>
        </thead>
        <tbody>"""
    for code, count in status_dist.items():
        html_content += f"<tr><td><code>{code}</code></td><td>{count}</td></tr>"

    html_content += """
        </tbody>
    </table>

</body>
</html>"""

    return html_content


def generate_log_export_file(data, format_type):
    """
    Génère un buffer binaire pour l'export HTML ou PDF du rapport d'analyse de logs.
    """
    fmt = format_type.lower()
    buffer = io.BytesIO()

    if fmt == 'html':
        html_str = build_html_report(data)
        buffer.write(html_str.encode('utf-8'))
        return buffer, 'text/html; charset=utf-8', 'log_analysis_report.html'

    elif fmt == 'pdf':
        if not PDF_SUPPORT:
            return None, None, None  # Module xhtml2pdf non installé

        html_str = build_html_report(data)
        pisa_status = pisa.CreatePDF(html_str, dest=buffer)

        if pisa_status.err:
            return None, None, None

        return buffer, 'application/pdf', 'log_analysis_report.pdf'

    return None, None, None