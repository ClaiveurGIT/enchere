import sqlite3
from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os, time, threading, random, base64

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration de la base de données
conn = sqlite3.connect('enchere.db', check_same_thread=False)
c = conn.cursor()

# Ajout des colonnes pour stocker les clés RSA
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, 
    username TEXT UNIQUE, 
    password TEXT, 
    public_key TEXT, 
    private_key TEXT
)''')
c.execute('''CREATE TABLE IF NOT EXISTS bids (id INTEGER PRIMARY KEY, user_id INTEGER, offer INTEGER, aes_key TEXT, iv TEXT, timestamp INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS auction (id INTEGER PRIMARY KEY, end_time INTEGER, min_bid INTEGER, winner TEXT, winning_bid INTEGER, status TEXT DEFAULT 'active')''')

# Initialisation de l'enchère avec un timer de 5 minutes et une mise minimale aléatoire
initial_time = int(time.time()) + 60  # 5 minutes à partir du lancement
min_bid = random.randint(200, 500)
c.execute("INSERT OR REPLACE INTO auction (id, end_time, min_bid, status) VALUES (1, ?, ?, 'active')", (initial_time, min_bid))
conn.commit()

# Fonction pour déchiffrer l'offre
def decrypt_offer(encrypted_offer_b64, iv_b64, aes_key_b64):
    encrypted_offer = base64.b64decode(encrypted_offer_b64)
    iv = base64.b64decode(iv_b64)
    aes_key = base64.b64decode(aes_key_b64)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(encrypted_offer) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return int(plaintext.decode('utf-8'))

# Vérification et mise à jour du timer
def timer_check():
    while True:
        c.execute("SELECT end_time, status FROM auction WHERE id = 1")
        auction_data = c.fetchone()

        if auction_data[1] == 'active' and time.time() >= auction_data[0]:
            c.execute("SELECT users.username, bids.offer FROM bids JOIN users ON bids.user_id = users.id")
            bids = c.fetchall()

            highest_bid = 0
            winner = None

            for bid in bids:
                try:
                    offer = int(bid[1])
                    if offer > highest_bid:
                        highest_bid = offer
                        winner = bid[0]
                except ValueError:
                    continue

            if winner:
                c.execute("UPDATE auction SET winner = ?, winning_bid = ?, status = 'ended' WHERE id = 1", (winner, highest_bid))
            else:
                c.execute("UPDATE auction SET status = 'ended' WHERE id = 1")
            conn.commit()

            c.execute("DELETE FROM bids")
            conn.commit()

        time.sleep(10)

threading.Thread(target=timer_check, daemon=True).start()

@app.route('/')
def index():
    c.execute("SELECT min_bid FROM auction WHERE id = 1")
    min_bid = c.fetchone()[0]
    return render_template('index.html', min_bid=min_bid)

@app.route('/get_timer', methods=['GET'])
def get_timer():
    c.execute("SELECT end_time, min_bid, winner, winning_bid, status FROM auction WHERE id = 1")
    auction_data = c.fetchone()
    time_remaining = max(0, auction_data[0] - int(time.time())) if auction_data[4] == 'active' else 0
    current_user = session.get('username')

    return jsonify({
        "time_remaining": time_remaining,
        "min_bid": auction_data[1],
        "winner": auction_data[2],
        "winning_bid": auction_data[3],
        "status": auction_data[4],
        "current_user": current_user
    })

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Utilisateur non connecté"})

    user_id = session['user_id']
    c.execute("SELECT public_key FROM users WHERE id = ?", (user_id,))
    public_key = c.fetchone()

    if public_key:
        return jsonify({"status": "success", "public_key": public_key[0]})
    else:
        return jsonify({"status": "error", "message": "Clé publique non trouvée"})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = generate_password_hash(data['password'])

    # Génération de la paire de clés RSA 4096 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Export des clés au format PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    try:
        c.execute("INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)",
                  (username, password, public_pem, private_pem))
        conn.commit()
        return jsonify({"status": "success", "message": "Utilisateur inscrit avec succès"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Nom d'utilisateur déjà pris"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if user and check_password_hash(user[2], password):
        session['user_id'] = user[0]
        session['username'] = user[1]
        return jsonify({"status": "success", "message": "Connexion réussie"})
    else:
        return jsonify({"status": "error", "message": "Identifiants incorrects"})

from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

@app.route('/bid', methods=['POST'])
def submit_bid():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Utilisateur non connecté"})

    # Vérifier si l'enchère est toujours active
    c.execute("SELECT status FROM auction WHERE id = 1")
    if c.fetchone()[0] == 'ended':
        return jsonify({"status": "error", "message": "L'enchère est terminée."})

    data = request.json
    encrypted_offer = data['encrypted_offer']
    iv = data['iv']
    encrypted_aes_key = data['aes_key']  # C'est maintenant la clé AES chiffrée avec RSA

    try:
        # 🔑 1. Récupérer la clé privée de l'utilisateur
        c.execute("SELECT private_key FROM users WHERE id = ?", (session['user_id'],))
        private_key_pem = c.fetchone()
        if not private_key_pem:
            return jsonify({"status": "error", "message": "Clé privée introuvable."})

        # 🔑 2. Importer la clé privée
        private_key = serialization.load_pem_private_key(
            private_key_pem[0].encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # 🔓 3. Déchiffrer la clé AES avec RSA-OAEP
        aes_key = private_key.decrypt(
            base64.b64decode(encrypted_aes_key),
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 🔐 4. Déchiffrer l'offre avec AES
        offer = decrypt_offer(encrypted_offer, iv, base64.b64encode(aes_key).decode('utf-8'))

    except Exception as e:
        print(f"Erreur de déchiffrement : {e}")
        return jsonify({"status": "error", "message": "Erreur de déchiffrement."})

    # Vérification de l'offre par rapport à l'enchère minimale
    c.execute("SELECT min_bid FROM auction WHERE id = 1")
    min_bid = c.fetchone()[0]

    if offer < min_bid:
        return jsonify({"status": "error", "message": f"L'offre doit être supérieure à {min_bid}"})

    # Vérifier si l'utilisateur a déjà soumis une enchère
    c.execute("SELECT * FROM bids WHERE user_id = ?", (session['user_id'],))
    if c.fetchone():
        return jsonify({"status": "error", "message": "Vous avez déjà soumis une enchère"})

    # Enregistrement de l'enchère
    c.execute("INSERT INTO bids (user_id, offer, aes_key, iv, timestamp) VALUES (?, ?, ?, ?, ?)",
              (session['user_id'], offer, encrypted_aes_key, iv, int(time.time())))
    conn.commit()

    return jsonify({"status": "success", "message": "Offre soumise avec succès"})


if __name__ == '__main__':
    app.run(debug=True)
