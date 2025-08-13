from flask import Flask, request, render_template, session, redirect, url_for, jsonify
import sqlite3
import logging
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey123'

# Setup logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (email TEXT PRIMARY KEY, password TEXT, public_key TEXT, key_verification_url TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_email TEXT, 
                  recipient_email TEXT, encrypted_message TEXT, encrypted_key TEXT, nonce TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        public_key = request.form['public_key']
        key_verification_url = request.form.get('key_verification_url', '')  # Optional
        
        session.clear()
        
        from werkzeug.security import generate_password_hash
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('DELETE FROM users WHERE email = ?', (email,))
            c.execute('INSERT INTO users (email, password, public_key, key_verification_url) VALUES (?, ?, ?, ?)', 
                     (email, hashed_password, public_key, key_verification_url))
            conn.commit()
            session['email'] = email
            logger.debug(f"User {email} signed up.")
            return render_template('signup.html', 
                                 message="Signup successful! Your public key has been saved. Copy it and post it to a public GitHub repository or Gist.",
                                 public_key=public_key, key_verification_url=key_verification_url)
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('signup.html', error="Email already exists")
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        session.clear()
        from werkzeug.security import check_password_hash
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            session['email'] = email
            logger.debug(f"User {email} logged in")
            return redirect(url_for('home'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/home')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, sender_email, encrypted_message, encrypted_key, nonce FROM messages WHERE recipient_email = ?', 
             (session['email'],))
    messages = c.fetchall()
    conn.close()
    
    # Messages are decrypted client-side, so pass raw data to template
    return render_template('home.html', messages=messages)

@app.route('/get_public_key', methods=['POST'])
def get_public_key():
    email = request.form.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT public_key, key_verification_url FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({'public_key': user[0], 'key_verification_url': user[1] or ''})
    return jsonify({'error': 'User not found'}), 404

@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if 'email' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        recipient_email = request.form['recipient_email']
        encrypted_message = request.form['encrypted_message']
        encrypted_key = request.form['encrypted_key']
        nonce = request.form['nonce']
        verification_url = request.form.get('verification_url', '')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT public_key, key_verification_url FROM users WHERE email = ?', (recipient_email,))
        user = c.fetchone()
        if not user:
            conn.close()
            return render_template('send_message.html', error="Recipient not found")
        
        recipient_public_key = '\n'.join(line.strip() for line in user[0].splitlines() if line.strip())
        db_verification_url = user[1] or ''
        
        # Verify public key if a URL is provided or stored
        warning = None
        if verification_url or db_verification_url:
            url_to_check = verification_url or db_verification_url
            try:
                response = requests.get(url_to_check, timeout=5)
                if response.status_code != 200 or recipient_public_key not in response.text:
                    conn.close()
                    return render_template('send_message.html', error="Public key verification failed: Key not found at URL or mismatch.")
            except requests.RequestException:
                warning = f"Could not verify public key at {url_to_check}. Proceeding without verification."
        else:
            warning = "No GitHub URL provided. The message will be encrypted with the stored public key, which may be less secure."
        
        try:
            c.execute('INSERT INTO messages (sender_email, recipient_email, encrypted_message, encrypted_key, nonce) VALUES (?, ?, ?, ?, ?)', 
                     (session['email'], recipient_email, encrypted_message, encrypted_key, nonce))
            conn.commit()
            conn.close()
            logger.debug(f"Message sent from {session['email']} to {recipient_email}")
            return render_template('send_message.html', message="Message sent successfully", warning=warning)
        except Exception as e:
            conn.close()
            logger.error(f"Error storing message: {str(e)}")
            return render_template('send_message.html', error=f"Error storing message: {str(e)}")
    return render_template('send_message.html')

@app.route('/delete_message', methods=['POST'])
def delete_message():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    message_id = request.form.get('message_id')
    if not message_id:
        return jsonify({'error': 'Message ID is required'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM messages WHERE id = ? AND recipient_email = ?', (message_id, session['email']))
    if c.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Message not found or unauthorized'}), 404
    conn.commit()
    conn.close()
    logger.debug(f"Message {message_id} deleted by {session['email']}")
    return jsonify({'success': 'Message deleted'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)