import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("EXIFTOOLS_API_KEY")
API_URL = "https://exiftools.com/api/v1/extract"
TEST_IMAGE_PATH = "/home/bojack/Lab/Eternal_Vault/eternal_vault/app/static/uploads/0d9b450501eb415496aab7d001a2a1e1.png"  # Remplace par un vrai chemin

headers = {
    "X-API-Key": API_KEY
}

if not os.path.exists(TEST_IMAGE_PATH):
    print(f"[-] Image de test introuvable : {TEST_IMAGE_PATH}")
    exit(1)

print(f"[+] Test de l'API ExifTools avec la clé : {API_KEY[:5]}***")

with open(TEST_IMAGE_PATH, 'rb') as f:
    files = {'file': f}
    res = requests.post(API_URL, headers=headers, files=files, timeout=10)

print(f"[+] Code de statut HTTP : {res.status_code}")
print(f"[+] Réponse : {res.text}")