# Secure File Sharing System  


**Project:** Secure File Sharing System  
**Tools Used:** Python Flask, Postman, Ngrok,curl  
**Prepared by:** Duncan Maganga  
**Date:** August 23, 2025    


## Executive Summary
This project forcused in desinging and implementing of secure file sharing system, I build a simple and effective platform that allows users to safely upload and download files as security being the primary consideration.
The system is mainly build using Python Flask for the backend and HTML for the frontend. To make sure that confidentiality is maintained to top notch I used AES encryption to all files at rest and during transer. I tested the system with **Postman** and **curl** and validated the system  performance.

## Purpose and Scope  

In today's digital lanscape alot of attacks have recorded and ensuring that we have a realiable mechanisms to exchange data without exposing them to unauthorized peoples, reducing the rate of cyber threats across industries such as healthcare, legal and finance we need a system with ensures confidentiality. The main purpose for this project was to desing and implement a sucure file sharing system that ensures top notch confidentiality, itergrity, and safe transer of data between users. 

## Tools and Methodology  

**Target:** Creating a Secure File Sharing System     
**Tools:** Ngrok, curl, Postman, Signal, ProtonMail, Keybase, Flask, VS Code    
**Approach:**  

            * Set up Flask to run the project creating virtual invirnment and installing pycryptodome  
            * Creating a basic route to handle uploads and downloads.    
            * Implement AES encryption rules and key management.    
            * Creating a basic HTML template containing basic login and handling file uploads and downloads.    
            * Testing with Postman and curl.  

## 1. Setting up Flask in Vs code

On your terminal create a folder where you will be running your project, set up a virtual environemnt and install all the Flask packages. 
create a basic app that will encrypt files before uploading and decrypting when downloading. 

### Quickstart  
This code has utilizes AES-GCM which combines authenticationin one step which is mostly used in TLS/HTTPS and secure file storage, it also ensures that when someone tampers with the data the tag verification fails during decryption, giving assuarance of confidentiality and integrity. 
The same key used for encryption is the same key used to decrypt the data this is achieved by wrapping the key with the master key stored encrypted together proving good key management.

```
import os, uuid, secrets, stat
from io import BytesIO
from datetime import timedelta
from flask import Flask, request, render_template, redirect, url_for, send_file, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET", os.urandom(32)),
    SQLALCHEMY_DATABASE_URI="sqlite:///app.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=128 * 1024 * 1024,  
    REMEMBER_COOKIE_DURATION=timedelta(days=7),
)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

STORAGE_DIR = "storage"
META_DIR = "meta"
MASTER_KEY_PATH = os.path.join(META_DIR, "master.key")
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pwd_hash = db.Column(db.String(256), nullable=False)

class FileRec(db.Model):
    id = db.Column(db.String(36), primary_key=True)      
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)  
    size = db.Column(db.Integer, nullable=False)          
    path = db.Column(db.String(255), nullable=False)      
    dek_nonce = db.Column(db.LargeBinary(12), nullable=False)
    dek_tag   = db.Column(db.LargeBinary(16), nullable=False)
    dek_wrapped = db.Column(db.LargeBinary, nullable=False)

with app.app_context():
    db.create_all()

def load_or_create_master_key() -> bytes:
    if "MASTER_KEY" in os.environ:
        k = bytes.fromhex(os.environ["MASTER_KEY"]) if all(c in "0123456789abcdefABCDEF" for c in os.environ["MASTER_KEY"]) else os.environ["MASTER_KEY"].encode()
        if len(k) != 32: raise ValueError("MASTER_KEY must be 32 bytes (hex or raw).")
        return k
    if os.path.exists(MASTER_KEY_PATH):
        return open(MASTER_KEY_PATH, "rb").read()
    k = secrets.token_bytes(32)  
    with open(MASTER_KEY_PATH, "wb") as f: f.write(k)
    try: os.chmod(MASTER_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)  
    except: pass
    return k

MASTER_KEY = load_or_create_master_key()
def aead_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ct  # [12|16|N]

def aead_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 28: raise ValueError("Blob too small")
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def wrap_dek(master_key: bytes, dek: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = secrets.token_bytes(12)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    wrapped, tag = cipher.encrypt_and_digest(dek)
    return nonce, tag, wrapped

def unwrap_dek(master_key: bytes, nonce: bytes, tag: bytes, wrapped: bytes) -> bytes:
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(wrapped, tag)

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        if not u or not p: flash("Username & password required"); return redirect(url_for("signup"))
        if User.query.filter_by(username=u).first(): flash("Username taken"); return redirect(url_for("signup"))
        user = User(username=u, pwd_hash=generate_password_hash(p))
        db.session.add(user); db.session.commit()
        login_user(user)
        return redirect(url_for("index"))
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if not user or not check_password_hash(user.pwd_hash, request.form["password"]):
            flash("Invalid credentials"); return redirect(url_for("login"))
        login_user(user, remember=True); return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
@app.route("/")
@login_required
def index():
    files = FileRec.query.filter_by(owner_id=current_user.id).all()
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files: abort(400)
    f = request.files["file"]
    if f.filename == "": abort(400)
    data = f.read()
    dek = secrets.token_bytes(32)
    enc_blob = aead_encrypt(dek, data) 
    n, t, wrapped = wrap_dek(MASTER_KEY, dek)

    file_id = str(uuid.uuid4())
    path = os.path.join(STORAGE_DIR, file_id)
    with open(path, "wb") as out: out.write(enc_blob)

    rec = FileRec(
        id=file_id, owner_id=current_user.id, filename=f.filename,
        size=len(data), path=path, dek_nonce=n, dek_tag=t, dek_wrapped=wrapped
    )
    db.session.add(rec); db.session.commit()
    flash("Uploaded & encrypted")
    return redirect(url_for("index"))

@app.route("/download/<file_id>")
@login_required
def download(file_id):
    rec = FileRec.query.filter_by(id=file_id, owner_id=current_user.id).first()
    if not rec or not os.path.exists(rec.path): abort(404)
    blob = open(rec.path, "rb").read()
    dek = unwrap_dek(MASTER_KEY, rec.dek_nonce, rec.dek_tag, rec.dek_wrapped)
    try:
        plaintext = aead_decrypt(dek, blob)
    except Exception:
        abort(400)  
    return send_file(BytesIO(plaintext), as_attachment=True, download_name=rec.filename)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)  
```


            

