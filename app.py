from flask import Flask, render_template, request, redirect, session, url_for, flash
import json, hashlib, secrets, os, base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)
DATA_FILE = "web_vault.json"

# --- Reusing Security Logic ---
def hash_password(password, salt=None):
    if salt is None: salt = secrets.token_bytes(16).hex()
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000)
    return pwd_hash.hex(), salt

def verify_password(stored_hash, salt, provided_password):
    new_hash, _ = hash_password(provided_password, salt)
    return new_hash == stored_hash

def xor_cipher(data, key_str):
    key = hashlib.sha256(key_str.encode()).digest()
    key_cycle = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes([b ^ k for b, k in zip(data, key_cycle)])

def encrypt(plaintext, master_pwd):
    return base64.b64encode(xor_cipher(plaintext.encode(), master_pwd)).decode()

def decrypt(ciphertext, master_pwd):
    return xor_cipher(base64.b64decode(ciphertext.encode()), master_pwd).decode()

def load_db():
    if not os.path.exists(DATA_FILE): return {}
    with open(DATA_FILE, 'r') as f: return json.load(f)

def save_db(data):
    with open(DATA_FILE, 'w') as f: json.dump(data, f, indent=4)

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form['username']
        mp = request.form['password']
        db = load_db()
        if user in db:
            flash("Username already exists!")
            return redirect(url_for('signup'))
        h, s = hash_password(mp)
        db[user] = {"master_hash": h, "salt": s, "credentials": []}
        save_db(db)
        flash("Registration successful! Please login.")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        mp = request.form['password']
        db = load_db()
        if user in db and verify_password(db[user]['master_hash'], db[user]['salt'], mp):
            session['user'] = user
            session['master_key'] = mp
            return redirect(url_for('vault'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/vault')
def vault():
    if 'user' not in session: return redirect(url_for('login'))
    db = load_db()
    creds = db.get(session['user'], {}).get('credentials', [])
    display_creds = []
    for c in creds:
        display_creds.append({
            'site': c['site'],
            'user': c['username'],
            'pwd': decrypt(c['password'], session['master_key'])
        })
    return render_template('vault.html', creds=display_creds, user=session['user'])

@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session: return redirect(url_for('login'))
    db = load_db()
    encrypted = encrypt(request.form['password'], session['master_key'])
    db[session['user']]['credentials'].append({
        'site': request.form['site'], 
        'username': request.form['username'], 
        'password': encrypted
    })
    save_db(db)
    return redirect(url_for('vault'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)