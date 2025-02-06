from mitmproxy import http
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_aes(aes_key_b64, encrypted_data_b64):
    try:
        aes_key = base64.b64decode(aes_key_b64)  # Décodage de la clé AES
        encrypted_data = base64.b64decode(encrypted_data_b64)  # Décodage des données chiffrées

        iv = encrypted_data[:16]  # L'IV est stocké au début du message
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_data.decode("utf-8").strip()
    except Exception as e:
        return f"Erreur de déchiffrement : {e}"

def request(flow: http.HTTPFlow):
    if "/bid" in flow.request.path and flow.request.method == "POST":
        try:
            data = json.loads(flow.request.content)
            aes_key = data.get("aes_key")
            encrypted_offer = data.get("hmac")  # Vérifie si l'offre est bien chiffrée

            print(f"[Intercepté] AES Key: {aes_key}")
            print(f"[Intercepté] Données chiffrées: {encrypted_offer}")

            if aes_key and encrypted_offer:
                decrypted_offer = decrypt_aes(aes_key, encrypted_offer)
                print(f"[Déchiffré] Offre soumise: {decrypted_offer}")

        except Exception as e:
            print(f"Erreur lors du traitement : {e}")
