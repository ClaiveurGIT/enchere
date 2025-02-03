import sqlite3
from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import os, time, threading, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration de la base de données
conn = sqlite3.connect('enchere.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS bids (id INTEGER PRIMARY KEY, user_id INTEGER, offer INTEGER, aes_key TEXT, hmac TEXT, timestamp INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS auction (id INTEGER PRIMARY KEY, end_time INTEGER, min_bid INTEGER)''')

# Initialisation de l'enchère avec un timer de 5 minutes et une mise minimale aléatoire
initial_time = int(time.time()) + 300  # 5 minutes à partir du lancement
min_bid = random.randint(200, 500)
c.execute("INSERT OR REPLACE INTO auction (id, end_time, min_bid) VALUES (1, ?, ?)", (initial_time, min_bid))
conn.commit()

# Vérification et mise à jour du timer
def timer_check():
    while True:
        c.execute("SELECT end_time FROM auction WHERE id = 1")
        end_time = c.fetchone()[0]

        if time.time() >= end_time:
            c.execute("SELECT users.username, MAX(bids.offer) FROM bids JOIN users ON bids.user_id = users.id")
            winner = c.fetchone()
            if winner[0]:
                print(f"L'utilisateur {winner[0]} a gagné avec l'offre de {winner[1]}")

            # Réinitialisation de la base de données après la fin de l'enchère
            c.execute("DELETE FROM bids")
            c.execute("DELETE FROM auction")
            conn.commit()

            # Redémarrer une nouvelle enchère
            new_end_time = int(time.time()) + 300
            new_min_bid = random.randint(200, 500)
            c.execute("INSERT INTO auction (id, end_time, min_bid) VALUES (1, ?, ?)", (new_end_time, new_min_bid))
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
    c.execute("SELECT end_time, min_bid FROM auction WHERE id = 1")
    auction_data = c.fetchone()
    time_remaining = max(0, auction_data[0] - int(time.time()))
    min_bid = auction_data[1]
    return jsonify({"time_remaining": time_remaining, "min_bid": min_bid})

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

    data = request.json
    offer = int(data['offer'])
    aes_key = data['aes_key']
    hmac_value = data['hmac']

    # Vérifier la mise minimale
    c.execute("SELECT min_bid FROM auction WHERE id = 1")
    min_bid = c.fetchone()[0]
    if offer < min_bid:
        return jsonify({"status": "error", "message": f"L'offre doit être supérieure à {min_bid}"})

    # Autoriser qu'une seule enchère par utilisateur
    c.execute("SELECT * FROM bids WHERE user_id = ?", (session['user_id'],))
    if c.fetchone():
        return jsonify({"status": "error", "message": "Vous avez déjà soumis une enchère"})

    c.execute("INSERT INTO bids (user_id, offer, aes_key, hmac, timestamp) VALUES (?, ?, ?, ?, ?)",
              (session['user_id'], offer, aes_key, hmac_value, int(time.time())))
    conn.commit()

    return jsonify({"status": "success", "message": "Offre soumise avec succès"})

if __name__ == '__main__':
    app.run(debug=True)
