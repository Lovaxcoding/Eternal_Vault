import os
import time
import json
import csv
import io
import hashlib
import requests
import subprocess
import dicttoxml

EXIFTOOLS_API_URL = "https://exiftools.com/api/v1/extract"
MAX_FILE_AGE = 3600  # 1 heure


def calculate_hashes(filepath):
    """Calcule les empreintes MD5, SHA-1 et SHA-256 du fichier."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }


def clean_old_uploads(upload_folder):
    """Supprime les fichiers datant de plus d'1 heure."""
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
        return

    now = time.time()
    for filename in os.listdir(upload_folder):
        file_path = os.path.join(upload_folder, filename)
        if os.path.isfile(file_path):
            if now - os.path.getmtime(file_path) > MAX_FILE_AGE:
                try:
                    os.remove(file_path)
                except OSError:
                    pass


def extract_local_exif(filepath):
    """Extraction locale de secours via ExifTool CLI (sans Pillow)."""
    data = {
        "source": "Local (ExifTool CLI)",
        "file_info": {
            "filename": os.path.basename(filepath),
            "size_bytes": os.path.getsize(filepath)
        },
        "hashes": calculate_hashes(filepath),
        "camera": {},
        "image_settings": {},
        "gps": {},
        "c2pa": {},
        "raw_tags": {}
    }

    try:
        # Exécution de la commande système exiftool avec sortie JSON
        result = subprocess.run(
            ['exiftool', '-json', '-c', '%.6f', filepath],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and result.stdout:
            exif_list = json.loads(result.stdout)
            if exif_list and isinstance(exif_list, list):
                meta = exif_list[0]

                # Informations sur le fichier
                data["file_info"]["dimensions"] = f"{meta.get('ImageWidth', 'N/A')}x{meta.get('ImageHeight', 'N/A')} px"
                data["file_info"]["format"] = meta.get('FileType', 'Inconnu')

                # Informations Appareil Photo
                data["camera"] = {
                    "Make": str(meta.get('Make', 'N/A')),
                    "Model": str(meta.get('Model', 'N/A')),
                    "Software": str(meta.get('Software', 'N/A')),
                    "LensModel": str(meta.get('LensModel', 'N/A'))
                }

                # Réglages Image
                data["image_settings"] = {
                    "DateTimeOriginal": str(meta.get('DateTimeOriginal', meta.get('CreateDate', 'N/A'))),
                    "ExposureTime": str(meta.get('ExposureTime', 'N/A')),
                    "FNumber": str(meta.get('FNumber', 'N/A')),
                    "ISO": str(meta.get('ISO', 'N/A'))
                }

                # Données GPS
                if 'GPSLatitude' in meta:
                    data["gps"]["latitude"] = meta.get('GPSLatitude')
                if 'GPSLongitude' in meta:
                    data["gps"]["longitude"] = meta.get('GPSLongitude')
                if 'GPSAltitude' in meta:
                    data["gps"]["altitude"] = meta.get('GPSAltitude')

                # Raw Tags (ensemble des métadonnées extraites)
                data["raw_tags"] = {k: str(v) for k, v in meta.items() if k not in ["SourceFile", "ExifToolVersion"]}

    except FileNotFoundError:
        data["error"] = "ExifTool n'est pas installé sur le système host (commande 'exiftool' introuvable)."
    except Exception as e:
        data["error"] = str(e)

    return data


def extract_api_exif(filepath, api_key):
    """Extraction complète via l'API ExifTools (EXIF, C2PA, Hashes)."""
    headers = {"X-API-Key": api_key}

    try:
        with open(filepath, 'rb') as f:
            files = {'file': f}
            response = requests.post(EXIFTOOLS_API_URL, headers=headers, files=files, timeout=30)

        if response.status_code == 200:
            res_json = response.json()
            if res_json.get("success"):
                metadata = res_json.get("metadata", {})
                exif = metadata.get("exif", {})
                c2pa = metadata.get("c2pa", {})

                data = {
                    "source": "API ExifTools",
                    "file_info": {
                        "filename": os.path.basename(filepath),
                        "size_bytes": os.path.getsize(filepath),
                        "dimensions": metadata.get("file_info", {}).get("dimensions", "Inconnu"),
                        "format": metadata.get("file_info", {}).get("format", "Inconnu"),
                        "uuid": res_json.get("uuid")
                    },
                    "hashes": res_json.get("hashes", calculate_hashes(filepath)),
                    "c2pa": c2pa,
                    "camera": {
                        "Make": exif.get("Make", "N/A"),
                        "Model": exif.get("Model", "N/A"),
                        "Software": exif.get("Software", "N/A"),
                        "LensModel": exif.get("LensModel", "N/A")
                    },
                    "image_settings": {
                        "DateTimeOriginal": exif.get("DateTimeOriginal", "N/A"),
                        "ExposureTime": exif.get("ExposureTime", "N/A"),
                        "FNumber": exif.get("FNumber", "N/A"),
                        "ISO": exif.get("ISO", "N/A")
                    },
                    "gps": metadata.get("gps", {}),
                    "raw_tags": {k: str(v) for k, v in metadata.items() if k not in ["exif", "gps", "c2pa", "file_info"]}
                }
                return data
            else:
                print(f"[EXIF API Error] Response not successful: {res_json}")
        else:
            print(f"[EXIF API Error] HTTP {response.status_code}: {response.text}")

        return None
    except Exception as e:
        print(f"[EXIF API Exception] {str(e)}")
        return None


def get_exif_metadata(filepath, api_key=None):
    """
    Chef d'orchestre : tente l'API en priorité si la clé est présente,
    sinon utilise l'extraction locale ExifTool CLI.
    """
    if api_key:
        api_result = extract_api_exif(filepath, api_key)
        if api_result:
            return api_result

    return extract_local_exif(filepath)


def generate_export_file(data, format_type):
    """
    Génère un buffer en mémoire pour le téléchargement direct du rapport EXIF.
    Formats supportés : json, csv, xml, txt.
    """
    buffer = io.BytesIO()
    fmt = format_type.lower()

    if fmt == 'json':
        content = json.dumps(data, indent=4, ensure_ascii=False)
        buffer.write(content.encode('utf-8'))
        mimetype = 'application/json'
        download_name = 'exif_metadata.json'

    elif fmt == 'xml':
        xml_bytes = dicttoxml.dicttoxml(data, custom_root='exif_report', attr_type=False)
        buffer.write(xml_bytes)
        mimetype = 'application/xml'
        download_name = 'exif_metadata.xml'

    elif fmt == 'csv':
        text_buffer = io.StringIO()
        writer = csv.writer(text_buffer)
        writer.writerow(['Category', 'Property', 'Value'])

        def flatten_to_csv(obj, category=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_cat = f"{category}.{k}" if category else k
                    if isinstance(v, dict):
                        flatten_to_csv(v, new_cat)
                    else:
                        writer.writerow([category or 'general', k, str(v)])

        flatten_to_csv(data)
        buffer.write(text_buffer.getvalue().encode('utf-8'))
        mimetype = 'text/csv'
        download_name = 'exif_metadata.csv'

    elif fmt in ['txt', 'text']:
        lines = [
            "==================================================",
            "        RAPPORT D'EXTRACTION DE METADONNEES       ",
            "==================================================",
            ""
        ]

        def render_txt(obj, indent=0):
            spacing = "  " * indent
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if isinstance(val, dict):
                        lines.append(f"\n{spacing}[ {key.upper()} ]")
                        render_txt(val, indent + 1)
                    else:
                        lines.append(f"{spacing}{key}: {val}")
            elif isinstance(obj, list):
                for item in obj:
                    render_txt(item, indent)

        render_txt(data)
        
        content = "\n".join(lines)
        buffer.write(content.encode('utf-8'))
        mimetype = 'text/plain; charset=utf-8'
        download_name = 'exif_metadata.txt'

    else:
        return None, None, None

    return buffer, mimetype, download_name