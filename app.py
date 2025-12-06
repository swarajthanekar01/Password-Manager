from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random session key
DB_NAME = "vault.db"

# --- Security Functions ---
def derive_key(master_password, salt):
    """Generates a 32-byte key from the master password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt(token, key):
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

# --- Database Setup ---
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # Table for the Master Salt (Required for KDF)
        c.execute('''CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, salt TEXT)''')
        # Table for Encrypted Passwords
        c.execute('''CREATE TABLE IF NOT EXISTS credentials 
                     (id INTEGER PRIMARY KEY, site TEXT, username TEXT, password TEXT)''')
        
        # Check if salt exists, if not create one
        c.execute("SELECT salt FROM config WHERE id=1")
        if not c.fetchone():
            salt = os.urandom(16).hex()
            c.execute("INSERT INTO config (id, salt) VALUES (1, ?)", (salt,))

def get_salt():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT salt FROM config WHERE id=1")
        return bytes.fromhex(c.fetchone()[0])

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    init_db() # Ensure DB exists
    if request.method == 'POST':
        mp = request.form['master_password']
        salt = get_salt()
        
        # Derive key and store in session (temporary memory)
        try:
            key = derive_key(mp, salt)
            # Test key by creating a Fernet instance
            Fernet(key) 
            session['key'] = key.decode()
            return redirect(url_for('dashboard'))
        except Exception:
            flash("Error generating key.")
            
    return render_template('index.html', page='login')

@app.route('/dashboard')
def dashboard():
    if 'key' not in session:
        return redirect(url_for('login'))
    
    key = session['key'].encode()
    decrypted_entries = []

    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT id, site, username, password FROM credentials")
            rows = c.fetchall()

            for row in rows:
                # We decrypt data before sending to HTML
                decrypted_entries.append({
                    'id': row[0],
                    'site': row[1], # Site name is NOT encrypted for easier searching
                    'username': decrypt(row[2], key),
                    'password': decrypt(row[3], key)
                })
    except Exception as e:
        flash("Decryption Failed: Master Password was incorrect.")
        return redirect(url_for('logout'))

    return render_template('index.html', page='dashboard', entries=decrypted_entries)

@app.route('/add', methods=['POST'])
def add():
    if 'key' not in session: return redirect(url_for('login'))
    
    key = session['key'].encode()
    site = request.form['site']
    # Encrypt sensitive fields
    user_enc = encrypt(request.form['username'], key)
    pass_enc = encrypt(request.form['password'], key)

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT INTO credentials (site, username, password) VALUES (?, ?, ?)",
                     (site, user_enc, pass_enc))
    
    flash("Password Saved!")
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
def delete(id):
    if 'key' not in session: return redirect(url_for('login'))
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM credentials WHERE id=?", (id,))
    flash("Entry Deleted.")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)