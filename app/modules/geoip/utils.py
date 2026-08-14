import urllib.request
import json

def get_geoip_data(ip_address: str = "") -> dict:
    """
    Récupère les informations géographiques et réseau d'une adresse IP.
    Si ip_address est vide, l'API renverra les infos de l'IP appelante.
    """
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'EternalVault/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'fail':
                return {'success': False, 'error': data.get('message', 'IP non valide')}
                
            return {'success': True, 'data': data}
    except Exception as e:
        return {'success': False, 'error': f"Erreur de connexion : {str(e)}"}