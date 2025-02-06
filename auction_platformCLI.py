import json
import os
import hashlib
import hmac
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DB_FILE = "auction_db.json"

SECRET_KEY = b"supersecretkeyforhmac"

def load_db():
    if not os.path.exists(DB_FILE):
        return {"users": {}, "auctions": {"Car Auction": {"starting_price": 5000, "bids": {}}}}
    with open(DB_FILE, "r") as file:
        return json.load(file)

def save_db(db):
    with open(DB_FILE, "w") as file:
        json.dump(db, file, indent=4)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode(), public_pem.decode()

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    hashed_password = kdf.derive(password.encode())
    return base64.b64encode(salt + hashed_password).decode()

def verify_password(stored_password, provided_password):
    stored_data = base64.b64decode(stored_password.encode())
    salt, stored_hash = stored_data[:16], stored_data[16:]
    new_hash = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    ).derive(provided_password.encode())
    return secrets.compare_digest(stored_hash, new_hash)

def register_user(username, password):
    db = load_db()
    if username in db["users"]:
        print("Username already taken.")
        return False
    private_key, public_key = generate_rsa_keys()
    hashed_password = hash_password(password)
    db["users"][username] = {
        "password": hashed_password,
        "private_key": private_key,
        "public_key": public_key,
    }
    save_db(db)
    return True

def login_user(username, password):
    db = load_db()
    return username in db["users"] and verify_password(db["users"][username]["password"], password)

def place_bid(username, auction_name, bid_amount):
    db = load_db()
    if auction_name not in db["auctions"] or username not in db["users"]:
        print("Invalid auction or user.")
        return False
    bid_signature = hmac.new(SECRET_KEY, str(bid_amount).encode(), hashlib.sha256).hexdigest()
    db["auctions"][auction_name]["bids"][username] = {
        "amount": bid_amount,
        "signature": bid_signature,
    }
    save_db(db)
    print(f"Bid of {bid_amount} placed by {username}.")
    return True

def finalize_auction(auction_name):
    db = load_db()
    if auction_name not in db["auctions"]:
        print("Auction not found.")
        return None
    bids = db["auctions"][auction_name]["bids"]
    if not bids:
        print("No valid bids.")
        return None
    winner = max(bids.items(), key=lambda x: x[1]["amount"])
    print(f"Auction won by {winner[0]} with bid {winner[1]['amount']}")
    return winner

if __name__ == "__main__":
    while True:
        print("1. Register User\n2. Login User\n3. Place Bid\n4. Finalize Auction\n5. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            register_user(username, password)
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            print("Login successful" if login_user(username, password) else "Invalid credentials")
        elif choice == "3":
            username = input("Enter username: ")
            bid_amount = int(input("Enter bid amount: "))
            place_bid(username, "Car Auction", bid_amount)
        elif choice == "4":
            finalize_auction("Car Auction")
        elif choice == "5":
            break

