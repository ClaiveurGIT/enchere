import sqlite3
from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os, time, threading, random, base64
import hmac
import hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)
HMAC_SECRET_KEY = b"0a 79 d8 c2 db 58 fe ad 03 3b 27 09 1f 7a 58 00 74 2a 10 00 3a 25 37 06 53 99 43 35 30 ce 21 80" 


def generate_hmac(message):
    if isinstance(message, str):
        message = message.encode()
    hmac_digest = hmac.new(HMAC_SECRET_KEY, message, hashlib.sha256).digest()
    return base64.b64encode(hmac_digest).decode()

# Configuration de la base de données
conn = sqlite3.connect('enchere.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
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

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = generate_password_hash(data['password'])

    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
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

@app.route('/bid', methods=['POST'])
def submit_bid():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Utilisateur non connecté"})

    c.execute("SELECT status FROM auction WHERE id = 1")
    if c.fetchone()[0] == 'ended':
        return jsonify({"status": "error", "message": "L'enchère est terminée."})

    data = request.json
    encrypted_offer = data['encrypted_offer']
    iv = data['iv']
    aes_key = data['aes_key']
    received_hmac = data['hmac']

    try:
        offer = decrypt_offer(encrypted_offer, iv, aes_key)
    except Exception:
        return jsonify({"status": "error", "message": "Erreur de déchiffrement."})

    c.execute("SELECT min_bid FROM auction WHERE id = 1")
    min_bid = c.fetchone()[0]

    if offer < min_bid:
        return jsonify({"status": "error", "message": f"L'offre doit être supérieure à {min_bid}"})

    # Vérification de l'HMAC
    message = f"{encrypted_offer}|{iv}|{aes_key}"
    expected_hmac = generate_hmac(message)
    print(expected_hmac)
    print(received_hmac)
    if not hmac.compare_digest(expected_hmac, received_hmac):
        return jsonify({"status": "error", "message": "Échec de vérification HMAC. Offre invalide."})

    c.execute("SELECT * FROM bids WHERE user_id = ?", (session['user_id'],))
    if c.fetchone():
        return jsonify({"status": "error", "message": "Vous avez déjà soumis une enchère"})

    c.execute("INSERT INTO bids (user_id, offer, aes_key, iv, timestamp) VALUES (?, ?, ?, ?, ?)",
              (session['user_id'], offer, aes_key, iv, int(time.time())))
    conn.commit()

    return jsonify({"status": "success", "message": "Offre soumise avec succès"})


if __name__ == '__main__':
    app.run(debug=True)