from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Form, Query
from fastapi.responses import StreamingResponse, HTMLResponse
from sqlalchemy.orm import Session
import io
import uuid
import os
import hashlib
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet

import models
from database import engine, get_db
import security

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Cryptographic Hybrid Vault Storage")
STORAGE_DIR = "./secure_storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

# Generate a local system encryption key specifically for securing logs
LOGS_CIPHER_KEY = Fernet.generate_key()
logs_cipher = Fernet(LOGS_CIPHER_KEY)

# Cryptographic Audit Log Helper Function
def log_action_securely(action: str, plain_message: str, db: Session):
    current_time = datetime.now(timezone.utc).replace(tzinfo=None)
    encrypted_msg_bytes = logs_cipher.encrypt(plain_message.encode('utf-8'))
    
    log_entry = models.AuditLog(
        timestamp=current_time,
        action=action,
        encrypted_message=encrypted_msg_bytes
    )
    db.add(log_entry)
    db.commit()

@app.post("/register/")
def register_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    priv_key, pub_key, upload_salt = security.generate_user_keypair()
    hashed_pwd = security.hash_password(password)
    new_user = models.User(username=username, hashed_password=hashed_pwd, private_key=priv_key, public_key=pub_key, upload_salt=upload_salt)
    db.add(new_user)
    db.commit()
    
    log_action_securely("REGISTER", f"Identity account created successfully for user: {username}", db)
    return {"message": "User registered with Advanced Cryptographic Salt Protection!"}

@app.post("/login/")
def login_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == username).first()
    if not db_user or not security.verify_password(password, db_user.hashed_password):
        log_action_securely("LOGIN_FAILED", f"Failed authentication attempt detected for username: {username}", db)
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    token = security.create_access_token(data={"user_id": db_user.id})
    log_action_securely("LOGIN_SUCCESS", f"User {username} logged in successfully. JWT Passport session assigned.", db)
    return {"access_token": token, "token_type": "bearer", "message": "Login successful!"}

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), token: str = Form(...), db: Session = Depends(get_db)):
    current_user_id = security.verify_access_token(token)
    user = db.query(models.User).filter(models.User.id == current_user_id).first()
    
    file_bytes = await file.read()
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    hasher.update(user.upload_salt.encode('utf-8'))
    computed_hash = hasher.hexdigest()
    
    duplicate_entry = db.query(models.File).filter(models.File.file_hash == computed_hash, models.File.owner_id == current_user_id).first()
    if duplicate_entry:
        log_action_securely("UPLOAD_BLOCKED", f"User {user.username} blocked from uploading duplicate content matching File ID {duplicate_entry.id}", db)
        raise HTTPException(status_code=400, detail=f"Blocked: This file already exists under ID {duplicate_entry.id}!")

    fresh_file_key = security.generate_fresh_file_key()
    encrypted_bytes = security.encrypt_data_with_key(file_bytes, fresh_file_key)
    hmac_tag = security.calculate_hmac(encrypted_bytes)
    encrypted_owner_key = security.encrypt_file_key_with_public_key(fresh_file_key, user.public_key)
    
    secure_filename = f"{uuid.uuid4()}.enc"
    file_path = os.path.join(STORAGE_DIR, secure_filename)
    with open(file_path, "wb") as f:
        f.write(encrypted_bytes)
        
    db_file = models.File(filename=file.filename, secure_name=secure_filename, owner_id=current_user_id, encrypted_owner_key=encrypted_owner_key, file_hash=computed_hash, hmac_tag=hmac_tag)
    db.add(db_file)
    db.commit()
    
    log_action_securely("UPLOAD", f"User {user.username} uploaded secure file: '{file.filename}' (Assigned File ID: {db_file.id})", db)
    return {"message": f"File encrypted & uploaded! File ID: {db_file.id}"}

@app.post("/share/")
def share_file(file_id: int = Form(...), share_with_username: str = Form(...), duration_minutes: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    current_user_id = security.verify_access_token(token)
    owner = db.query(models.User).filter(models.User.id == current_user_id).first()
    db_file = db.query(models.File).filter(models.File.id == file_id).first()
    if not db_file or db_file.owner_id != current_user_id:
        log_action_securely("SHARE_VIOLATION", f"User ID {current_user_id} triggered an unauthorized share warning vector on File ID {file_id}", db)
        raise HTTPException(status_code=403, detail="Unauthorized share action request.")
        
    recipient = db.query(models.User).filter(models.User.username == share_with_username).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient username not found.")
        
    raw_file_key = security.decrypt_file_key_with_private_key(db_file.encrypted_owner_key, owner.private_key)
    encrypted_recipient_key = security.encrypt_file_key_with_public_key(raw_file_key, recipient.public_key)
    expiry_time = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=duration_minutes)
    
    existing_share = db.query(models.SharedFileKey).filter(models.SharedFileKey.file_id == file_id, models.SharedFileKey.user_id == recipient.id).first()
    if existing_share:
        existing_share.encrypted_recipient_key = encrypted_recipient_key
        existing_share.expires_at = expiry_time
        db.commit()
    else:
        new_share = models.SharedFileKey(user_id=recipient.id, file_id=file_id, encrypted_recipient_key=encrypted_recipient_key, expires_at=expiry_time)
        db.add(new_share)
        db.commit()
        
    log_action_securely("SHARE", f"Owner {owner.username} granted token key access to recipient {share_with_username} for file ID {file_id} (Expires in {duration_minutes}m)", db)
    return {"message": f"File key cryptographically shared with {share_with_username} for {duration_minutes} minutes!"}

@app.get("/download/{file_id}")
def download_file(file_id: int, token: str = Query(...), db: Session = Depends(get_db)):
    current_user_id = security.verify_access_token(token)
    user = db.query(models.User).filter(models.User.id == current_user_id).first()
    db_file = db.query(models.File).filter(models.File.id == file_id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File records not found.")
        
    file_path = os.path.join(STORAGE_DIR, db_file.secure_name)
    with open(file_path, "rb") as f:
        encrypted_payload = f.read()
        
    if not security.verify_hmac(encrypted_payload, db_file.hmac_tag):
        log_action_securely("TAMPER_CRITICAL", f"CRITICAL CORRUPTION: File ID {file_id} failed HMAC integrity checking validation parameters!", db)
        raise HTTPException(status_code=400, detail="SECURITY WARNING: File integrity check failed!")
        
    raw_file_key = None
    if db_file.owner_id == current_user_id:
        raw_file_key = security.decrypt_file_key_with_private_key(db_file.encrypted_owner_key, user.private_key)
    else:
        shared_entry = db.query(models.SharedFileKey).filter(models.SharedFileKey.file_id == file_id, models.SharedFileKey.user_id == current_user_id).first()
        if not shared_entry:
            log_action_securely("DOWNLOAD_DENIED", f"User {user.username} blocked from requesting file ID {file_id} due to missing permissions.", db)
            raise HTTPException(status_code=403, detail="Access Denied.")
            
        current_time = datetime.now(timezone.utc).replace(tzinfo=None)
        if current_time > shared_entry.expires_at:
            db.delete(shared_entry)
            db.commit()
            log_action_securely("LINK_EXPIRED", f"User {user.username} request for file ID {file_id} rejected because the time-bound token window expired.", db)
            raise HTTPException(status_code=403, detail="Access Denied: Link Expired.")
            
        raw_file_key = security.decrypt_file_key_with_private_key(shared_entry.encrypted_recipient_key, user.private_key)
        
    decrypted_data = security.decrypt_data_with_key(encrypted_payload, raw_file_key)
    log_action_securely("DOWNLOAD", f"User {user.username} downloaded and decrypted file ID {file_id} successfully.", db)
    return StreamingResponse(io.BytesIO(decrypted_data), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={db_file.filename}"})

@app.post("/delete/")
def delete_file(file_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    current_user_id = security.verify_access_token(token)
    user = db.query(models.User).filter(models.User.id == current_user_id).first()
    db_file = db.query(models.File).filter(models.File.id == file_id).first()
    if not db_file or db_file.owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="Unauthorized deletion request.")
        
    file_path = os.path.join(STORAGE_DIR, db_file.secure_name)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.delete(db_file)
    db.commit()
    
    log_action_securely("PURGE", f"Owner {user.username} issued data shred instruction on File ID {file_id}. File purged.", db)
    return {"message": "File wiped cleanly from filesystem!"}

@app.get("/admin/logs/")
def get_audit_logs(db: Session = Depends(get_db)):
    raw_logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).all()
    decrypted_logs = []
    for log in raw_logs:
        try:
            decrypted_msg = logs_cipher.decrypt(log.encrypted_message).decode('utf-8')
        except Exception:
            decrypted_msg = "[MALFORMED OR TAMPERED CIPHERTEXT DATA]"
            
        decrypted_logs.append({
            "id": log.id,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "action": log.action,
            "message": decrypted_msg
        })
    return decrypted_logs

@app.get("/", response_class=HTMLResponse)
async def read_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Advanced Cryptographic Hybrid Vault</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #ffffff; margin: 40px; }
            .container { max-width: 800px; margin: auto; background: #1e1e1e; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
            h1 { color: #00adb5; border-bottom: 2px solid #393e46; padding-bottom: 10px; }
            h2 { color: #eeeeee; margin-top: 30px; }
            .box { background: #222831; padding: 20px; border-radius: 6px; margin-bottom: 20px; border-left: 4px solid #00adb5; }
            input[type="text"], input[type="password"], input[type="file"], input[type="number"] { width: 95%; padding: 10px; margin: 10px 0; border-radius: 4px; border: 1px solid #393e46; background: #393e46; color: #fff; }
            button { background-color: #00adb5; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 5px; }
            button:hover { background-color: #007a80; }
            .response-box { background: #121212; padding: 12px; border-radius: 4px; margin-top: 12px; border: 1px dashed #393e46; font-family: monospace; word-break: break-all; color: #ffc107; display: none; }
            .log-line { border-bottom: 1px solid #393e46; padding: 6px 0; font-family: monospace; font-size: 13px; }
            .log-time { color: #888; }
            .log-action { color: #00adb5; font-weight: bold; padding: 0 6px; }
            .log-msg { color: #ffc107; }
            /* Footer Signature Box Styles */
            .footer-sig { text-align: center; margin-top: 30px; padding-top: 15px; border-top: 1px solid #393e46; font-size: 14px; color: #888; font-weight: 500; letter-spacing: 1px; }
            .footer-sig span { color: #00adb5; font-weight: bold; text-shadow: 0 0 8px rgba(0, 173, 181, 0.4); }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Advanced Cryptographic Hybrid Vault</h1>
            <p>Production-Grade Storage Engine with Shielded Tamper-Proof Audit Logging.</p>
            
            <div class="box">
                <h2>👤 Identity Portal (Register / Log In)</h2>
                <h3>Register Account</h3>
                <form id="registerForm"><input type="text" id="regUser" placeholder="Choose Username" required><br><input type="password" id="regPass" placeholder="Choose Password" required><br><button type="submit">Register Identity</button></form>
                <div id="regResponse" class="response-box"></div>
                <h3 style="margin-top:20px;">Log In</h3>
                <form id="loginForm"><input type="text" id="logUser" placeholder="Username" required><br><input type="password" id="logPass" placeholder="Password" required><br><button type="submit" style="background-color: #28a745;">Log In (Get Passport Token)</button></form>
                <div id="loginResponse" class="response-box" style="color: #28a745;"></div>
            </div>

            <div class="box">
                <h2>📤 Token-Authorized Secure Upload</h2>
                <form id="uploadForm"><input type="text" id="uploadToken" placeholder="Paste Passport Token here" required><br><input type="file" id="uploadFile" required><br><button type="submit">Encrypt Payload & Save</button></form>
                <div id="uploadResponse" class="response-box"></div>
            </div>

            <div class="box">
                <h2>🤝 Cryptographic Sharing Engine</h2>
                <form id="shareForm">
                    <input type="text" id="shareToken" placeholder="Paste Passport Token here" required><br>
                    <input type="text" id="shareFileId" placeholder="File ID" required><br>
                    <input type="text" id="shareTargetUser" placeholder="Target Username" required><br>
                    <input type="number" id="shareDuration" placeholder="Lifespan Duration Window (in Minutes)" min="1" required><br>
                    <button type="submit" style="background-color: #ffc107; color: #000;">Wrap & Share File Key</button>
                </form>
                <div id="shareResponse" class="response-box"></div>
            </div>

            <div class="box" style="border-left-color: #dc3545;">
                <h2>🗑️ File Shredder Engine</h2>
                <form id="deleteForm"><input type="text" id="deleteToken" placeholder="Paste Passport Token here" required><br><input type="text" id="deleteFileId" placeholder="Enter File ID to delete" required><br><button type="submit" style="background-color: #dc3545;">Shred Data Chunk</button></form>
                <div id="deleteResponse" class="response-box" style="color: #dc3545;"></div>
            </div>

            <div class="box" style="border-left-color: #28a745;">
                <h2>📥 Secure Download Vault</h2>
                <form id="downloadForm"><input type="text" id="downloadToken" placeholder="Paste Passport Token here" required><br><input type="text" id="downloadFileId" placeholder="Enter File ID to fetch" required><br><button type="submit" style="background-color: #28a745;">Decrypt & Download Stream</button></form>
                <div id="downloadResponse" class="response-box" style="color: #dc3545;"></div>
            </div>

            <div class="box" style="border-left-color: #00adb5; background: #111;">
                <h2>🪵 Live Cryptographic SIEM Audit Logs</h2>
                <p style="font-size: 12px; color: #888;">System log payloads decrypting on the fly for system administrators...</p>
                <div id="logConsole" style="max-height: 200px; overflow-y: auto; background: #000; padding: 10px; border-radius: 4px;">
                    <p style="color: #666;">Awaiting infrastructure interactions...</p>
                </div>
                <button onclick="refreshAuditLogs()" style="background-color: #393e46; font-size:11px; padding: 5px 10px; margin-top: 10px;">Query Log Database</button>
            </div>
            
            <div class="footer-sig">
                🚀 System Architecture Developed by: <span>ARIP</span>
            </div>
        </div>
        <script>
            function showResponse(elementId, text) { var el = document.getElementById(elementId); el.style.display = "block"; el.innerText = text; }
            
            function refreshAuditLogs() {
                fetch('/admin/logs/').then(res => res.json()).then(logs => {
                    var consoleEl = document.getElementById('logConsole');
                    consoleEl.innerHTML = "";
                    if(logs.length === 0) { consoleEl.innerHTML = "<p style='color:#666;'>No logs recorded yet.</p>"; return; }
                    logs.forEach(log => {
                        consoleEl.innerHTML += `<div class='log-line'><span class='log-time'>[${log.timestamp}]</span><span class='log-action'>${log.action}</span>:<span class='log-msg'> ${log.message}</span></div>`;
                    });
                });
            }

            document.getElementById('registerForm').addEventListener('submit', function(e) { e.preventDefault(); var data = new FormData(); data.append('username', document.getElementById('regUser').value); data.append('password', document.getElementById('regPass').value); fetch('/register/', { method: 'POST', body: data }).then(res => res.json()).then(r => { showResponse('regResponse', r.detail ? "Error: " + r.detail : r.message); refreshAuditLogs(); }); });
            document.getElementById('loginForm').addEventListener('submit', function(e) { e.preventDefault(); var data = new FormData(); data.append('username', document.getElementById('logUser').value); data.append('password', document.getElementById('logPass').value); fetch('/login/', { method: 'POST', body: data }).then(res => res.json()).then(r => { showResponse('loginResponse', r.access_token ? "Access Token: " + r.access_token : "Error: " + r.detail); refreshAuditLogs(); }); });
            
            document.getElementById('uploadForm').addEventListener('submit', function(e) { 
                e.preventDefault(); var btn = e.target.querySelector('button'); btn.disabled = true; btn.innerText = "Encrypting & Saving...";
                var data = new FormData(); data.append('token', document.getElementById('uploadToken').value); data.append('file', document.getElementById('uploadFile').files[0]); 
                fetch('/upload/', { method: 'POST', body: data }).then(res => {
                    return res.json().then(jsonBody => {
                        if (!res.ok) { return { error: true, message: jsonBody.detail || "Upload failed." }; }
                        return { error: false, message: jsonBody.message };
                    });
                }).then(result => {
                    showResponse('uploadResponse', result.message); btn.disabled = false; btn.innerText = "Encrypt Payload & Save"; refreshAuditLogs();
                }).catch(() => {
                    showResponse('uploadResponse', "Error: Connection failed."); btn.disabled = false; btn.innerText = "Encrypt Payload & Save";
                });
            });
            
            document.getElementById('shareForm').addEventListener('submit', function(e) { 
                e.preventDefault(); var data = new FormData(); data.append('token', document.getElementById('shareToken').value); data.append('file_id', document.getElementById('shareFileId').value); data.append('share_with_username', document.getElementById('shareTargetUser').value); data.append('duration_minutes', document.getElementById('shareDuration').value); 
                fetch('/share/', { method: 'POST', body: data }).then(res => res.json()).then(r => { showResponse('shareResponse', r.detail ? "Error: " + r.detail : r.message); refreshAuditLogs(); }); 
            });
            
            document.getElementById('deleteForm').addEventListener('submit', function(e) { e.preventDefault(); var data = new FormData(); data.append('token', document.getElementById('deleteToken').value); data.append('file_id', document.getElementById('deleteFileId').value); fetch('/delete/', { method: 'POST', body: data }).then(res => res.json()).then(r => { showResponse('deleteResponse', r.detail ? "Error: " + r.detail : r.message); refreshAuditLogs(); }); });
            
            document.getElementById('downloadForm').addEventListener('submit', function(e) { 
                e.preventDefault(); var token = document.getElementById('downloadToken').value; var fileId = document.getElementById('downloadFileId').value; var targetUrl = '/download/' + fileId + '?token=' + encodeURIComponent(token);
                fetch(targetUrl).then(res => {
                    if(!res.ok) { return res.json().then(err => { showResponse('downloadResponse', "Error: " + err.detail); refreshAuditLogs(); }); }
                    window.location.href = targetUrl; setTimeout(refreshAuditLogs, 500);
                }).catch(() => { showResponse('downloadResponse', "Network connection failure."); });
            });

            window.onload = refreshAuditLogs;
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)