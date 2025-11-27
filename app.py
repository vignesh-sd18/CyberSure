# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Policy, Decb, Booking , AttackEvent
from eth_account import Account
from datetime import datetime, timedelta
import joblib
import re
import threading
import numpy as np
import hashlib
import pandas as pd
from web3 import Web3
import json
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter
from dotenv import load_dotenv
import secrets
from flask import session, render_template
import secrets
from flask import session
import secrets


load_dotenv()

# -----------------------
# Initialize Flask App
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
dats = "Medium"


attacks = "attacks_bp"
# -----------------------
# Initialize Extensions
# -----------------------
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user:
        print(f"Loaded user: {user.username}, Role: {user.role}")
    return user



# -----------------------------
# Web3 & Contract Setup
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
if not w3.is_connected():
    raise Exception("Cannot connect to Ganache. Make sure Ganache is running!")

# Backend account (to pay gas)
backend_private_key = os.environ.get("backend_private_key")
backend_account = Account.from_key(backend_private_key)

# Check balance
balance = w3.eth.get_balance(backend_account.address)
print("Backend balance:", w3.from_wei(balance, 'ether'), "ETH")

# Load contract ABI and bytecode
with open(os.path.join(BASE_DIR, 'build', 'compiled_contract.json'), 'r') as f:
    compiled_contract = json.load(f)

# Update to match your Solidity contract name
contract_abi = compiled_contract['contracts']['MyContract.sol']['CyberInsurance']['abi']
contract_bytecode = compiled_contract['contracts']['MyContract.sol']['CyberInsurance']['evm']['bytecode']['object']

# Get deployed contract address from environment variable (if any)
contract_address = os.environ.get("contract_address", "")

# Deploy contract if no address provided
if not contract_address or contract_address.lower() == '0xyourdeployedcontractaddressonganache':
    Contract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
    tx_hash = Contract.constructor().transact({'from': backend_account.address})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = receipt.contractAddress
    print("Contract deployed at:", contract_address)

# Create contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# -----------------------
# Routes
# -----------------------
@app.route('/')
def index():
    return render_template('index.html')






@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         email = request.form.get('email')
#         password = request.form.get('password')

#         # Check if email already exists
#         existing_user = User.query.filter_by(email=email).first()
#         if existing_user:
#             flash('Email already registered. Please login or use a different email.', 'warning')
#             return redirect(url_for('register'))

#         # Generate Ethereum wallet for the user (private key never stored)
#         acct = Account.create()
#         wallet_address = acct.address
#         balance = w3.eth.get_balance(backend_account.address)
#         print("Backend balance:", Web3.from_wei(balance, 'ether'), "ETH")

#         # Hash password only
#         hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

#         # Save user in DB
#         new_user = User(
#             username=username,
#             email=email,
#             password=hashed_password,
#             wallet_address=wallet_address,
#             kyc_verified=False
#         )
#         db.session.add(new_user)
#         db.session.commit()

#         # Call smart contract from backend account
#         nonce = w3.eth.get_transaction_count(backend_account.address)
#         tx = contract.functions.registerUser(wallet_address, username).build_transaction({
#         'from': backend_account.address,
#         'nonce': nonce,
#         'gas': 500000,
#         'gasPrice': Web3.to_wei('20', 'gwei'),
#         'value': 0 })


#         signed_tx = w3.eth.account.sign_transaction(tx, backend_private_key)
#         tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        

#         print(f"Registration transaction sent: {tx_hash.hex()}")

#         flash('Registration successful! Wallet created and registered on blockchain.', 'success')
#         return redirect(url_for('login'))

#     return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         password = request.form.get('password')
#         user = User.query.filter_by(email=email).first()
        
#         if user and check_password_hash(user.password, password):
#             login_user(user)
#             flash('Logged in successfully!', 'success')

#             # Redirect based on role
#             if user.role == 'admin':
#                 return redirect(url_for('admin_dashboard'))  # Admin route
#             else:
#                 return redirect(url_for('predict_risk'))  # Customer route

#         else:
#             flash('Invalid email or password.', 'danger')
#             return redirect(url_for('login'))

#     return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please login or use a different email.', 'warning')
            return redirect(url_for('register'))

      
        acct = Account.create()
        wallet_address = acct.address
        balance = w3.eth.get_balance(backend_account.address)
        print("Backend balance:", Web3.from_wei(balance, 'ether'), "ETH")

        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Save user in DB
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            wallet_address=wallet_address,
            kyc_verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        # Call smart contract from backend account
        nonce = w3.eth.get_transaction_count(backend_account.address)
        tx = contract.functions.registerUser(wallet_address, username).build_transaction({
            'from': backend_account.address,
            'nonce': nonce,
            'gas': 500000,
            'gasPrice': Web3.to_wei('20', 'gwei'),
            'value': 0
        })
        signed_tx = w3.eth.account.sign_transaction(tx, backend_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"Registration transaction sent: {tx_hash.hex()}")

      
        session_token = secrets.token_hex(32)
        session['token'] = session_token

       
        print(f"Token (Register): {session_token}")

        #return redirect(url_for('login' , token=session_token))
        return render_template('register.html', token=session_token)

    return render_template('register.html')





# SQLi and token detection
SQLI_KEYWORDS = ["'", '"', ";", "--", "/*", "*/", " OR ", " AND ", "1=1", "DROP", "SELECT", "INSERT", "UPDATE", "DELETE"]
TOKEN_HEX_PATTERN = re.compile(r'\b[0-9a-fA-F]{64}\b')

# In-memory brute-force protection
FAILED_ATTEMPTS = {}    
BANNED_IPS = {}         
LOCK = threading.Lock()


MAX_FAILED = 5          
WINDOW_SECONDS = 300     
BAN_SECONDS = 600     
def log_to_file(filename: str, text: str):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def is_ip_banned(ip: str) -> bool:
    """Check if IP is currently banned and cleanup expired bans."""
    with LOCK:
        expiry = BANNED_IPS.get(ip)
        if expiry:
            if datetime.utcnow() < expiry:
                return True
            else:
                
                del BANNED_IPS[ip]
    return False

def record_failed_attempt(ip: str):
    """Record failed login attempt and ban if threshold exceeded."""
    now = datetime.utcnow()
    with LOCK:
        entry = FAILED_ATTEMPTS.get(ip)
        if not entry:
            FAILED_ATTEMPTS[ip] = {"count": 3, "first_failure": now}
            return
       
        first = entry["first_failure"]
        if (now - first).total_seconds() <= WINDOW_SECONDS:
            entry["count"] += 1
        else:
            
            FAILED_ATTEMPTS[ip] = {"count": 3, "first_failure": now}
            return
       
        if entry["count"] >= MAX_FAILED:
            BANNED_IPS[ip] = now + timedelta(seconds=BAN_SECONDS)
            
            if ip in FAILED_ATTEMPTS:
                del FAILED_ATTEMPTS[ip]

def reset_failed_attempts(ip: str):
    with LOCK:
        if ip in FAILED_ATTEMPTS:
            del FAILED_ATTEMPTS[ip]

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = (request.form.get('email') or "").strip()
#         password = (request.form.get('password') or "").strip()
#         user_ip = request.remote_addr or "unknown"

      
#         suspicious = False
#         suspicious_reasons = []

        
#         for kw in SQLI_KEYWORDS:
#             if kw.lower() in email.lower() or kw.lower() in password.lower():
#                 suspicious = True
#                 suspicious_reasons.append(f"keyword:{kw}")
#                 break

        
#         if TOKEN_HEX_PATTERN.search(email) or TOKEN_HEX_PATTERN.search(password):
#             suspicious = True
#             suspicious_reasons.append("token_pattern_detected")

       
#         if len(email) > 320 or len(password) > 1024:
#             suspicious = True
#             suspicious_reasons.append("oversized_input")

#         timestamp = datetime.utcnow().isoformat()

       
#         base_log = f"[{timestamp}] IP:{user_ip} | Email:{email} | Suspicious:{suspicious} | Reasons:{','.join(suspicious_reasons)}"

#         if suspicious:
            
#             log_to_file("sql_injection_attempts.txt", base_log)
           
#             log_to_file("login_attempts.txt", base_log + " | ACTION:BLOCKED_SUSPICIOUS")

           
#             flash("Suspicious input sql_injection detected. Your attempt has been logged.", "danger")
#             return redirect(url_for('login'))

#         # ---------- 2) Normal login flow: look up user ----------
#         user = User.query.filter_by(email=email).first()

#         if user and check_password_hash(user.password, password):
#             # Successful login
#             login_user(user)
#             session_token = secrets.token_hex(32)
#             session['token'] = session_token

#             # Log success. NOTE: In production consider not logging full token.
#             success_log = base_log + f" | RESULT:SUCCESS | UserID:{user.id} | Token:{session_token}"
#             log_to_file("login_attempts.txt", success_log)

#             print(f"Session Token (Login): {session_token}")  
           
#             if user.role == 'admin':
#                 return redirect(url_for('admin_dashboard'))  
#             else:
#                 return redirect(url_for('predict_risk'))

#         else:
#             # Failed login (invalid credentials)
#             fail_log = base_log + " | RESULT:FAILED_LOGIN"
#             log_to_file("login_attempts.txt", fail_log)

#             flash('Invalid email or password.', 'danger')
#             return redirect(url_for('login'))

#     # GET -> render login page
#     return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or "").strip()
        password = (request.form.get('password') or "").strip()
        user_ip = request.remote_addr or "unknown"
        timestamp = datetime.utcnow().isoformat()

       
        if is_ip_banned(user_ip):
            ban_expiry = BANNED_IPS.get(user_ip)
            log_to_file("login_attempts.txt", f"[{timestamp}] IP:{user_ip} | Email:{email} | BLOCKED:IP_BANNED until {ban_expiry.isoformat()}")
            flash("⚠️ Brute Force Attack Detected: Your IP has been temporarily blocked due to multiple failed login attempts. Please try again later. Your account security is our priority.", "danger")
            return redirect(url_for('login'))

      
        suspicious = False
        suspicious_reasons = []

        for kw in SQLI_KEYWORDS:
            if kw.lower() in email.lower() or kw.lower() in password.lower():
                suspicious = True
                suspicious_reasons.append(f"keyword:{kw}")
                break

        if TOKEN_HEX_PATTERN.search(email) or TOKEN_HEX_PATTERN.search(password):
            suspicious = True
            suspicious_reasons.append("token_pattern_detected")

        if len(email) > 320 or len(password) > 1024:
            suspicious = True
            suspicious_reasons.append("oversized_input")

        base_log = f"[{timestamp}] IP:{user_ip} | Email:{email} | Suspicious:{suspicious} | Reasons:{','.join(suspicious_reasons)}"

        if suspicious:
           
            log_to_file("sql_injection_attempts.txt", base_log)
            log_to_file("login_attempts.txt", base_log + " | ACTION:BLOCKED_SUSPICIOUS")

           
            with LOCK:
                BANNED_IPS[user_ip] = datetime.utcnow() + timedelta(seconds=BAN_SECONDS)
                if user_ip in FAILED_ATTEMPTS:
                    del FAILED_ATTEMPTS[user_ip]

            flash("🛡️ Security Alert: Potential SQL Injection Attack Detected. Your attempt has been blocked and logged. If you believe this is a mistake, please contact support.", "danger")
            return redirect(url_for('login'))

        # 2) Normal login flow
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Successful login
            login_user(user)
            session_token = secrets.token_hex(32)
            session['token'] = session_token
            # Reset any company upload multi-step session state for a fresh login
            session.pop('company_step', None)
            session.pop('company_otp', None)
            session.pop('last_phish_info', None)

            # Reset failed counters for this IP on success
            reset_failed_attempts(user_ip)

            success_log = base_log + f" | RESULT:SUCCESS | UserID:{user.id} | Token:{session_token}"
            log_to_file("login_attempts.txt", success_log)
            print(f"Session Token (Login): {session_token}") 

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('predict_risk'))

        else:
            # Failed login: record and maybe ban
            record_failed_attempt(user_ip)
            fail_log = base_log + " | RESULT:FAILED_LOGIN"
            log_to_file("login_attempts.txt", fail_log)

            # If we just banned them in record_failed_attempt, log that too
            if is_ip_banned(user_ip):
                ban_until = BANNED_IPS[user_ip].isoformat()
                log_to_file("login_attempts.txt", f"[{timestamp}] IP:{user_ip} | ACTION:IP_BANNED until {ban_until}")

            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    # GET -> render login page
    return render_template('login.html')



# -----------------------
# Load ML models
# -----------------------
scaler = joblib.load("ml_models/scaler.pkl")
trained_columns = joblib.load("ml_models/trained_columns.pkl")
rf_model = joblib.load("ml_models/random_forest_model.pkl")
risk_map = {0: "Low", 1: "Medium", 2: "High"}

def preprocess_input(input_data):
    df = pd.DataFrame([input_data])
    for col in ['Income', 'Coverage Amount', 'Premium Amount', 'Deductible']:
        if col in df.columns:
            df[col] = np.log1p(df[col])
    if 'Income' in df.columns and 'Premium Amount' in df.columns:
        df['Income_to_Premium'] = df['Income'] / (df['Premium Amount'] + 1)
    if 'Coverage Amount' in df.columns and 'Income' in df.columns:
        df['Coverage_to_Income'] = df['Coverage Amount'] / (df['Income'] + 1)
    df = pd.get_dummies(df)
    missing_cols = [col for col in trained_columns if col not in df.columns]
    if missing_cols:
        df = pd.concat([df, pd.DataFrame(0, index=df.index, columns=missing_cols)], axis=1)
    df = df[trained_columns]
    return scaler.transform(df)


@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict_risk():
    result = None

    # Check KYC status first
    if not current_user.kyc_verified:
        result = {"error": "Your KYC is not verified yet. Please wait for verification to make predictions."}
        return render_template("predict.html", result=result)

    if request.method == 'POST':
        try:
            # Collect input data from form
            income = float(request.form.get("income", 0))
            coverage = float(request.form.get("coverage", 0))
            premium = float(request.form.get("premium", 0))
            deductible = float(request.form.get("deductible", 0))
            occupation = request.form.get("occupation", "Other")
            geo = request.form.get("geo", "Other")
            products = request.form.get("products", "Other")

            input_data = {
                "Income": income,
                "Coverage Amount": coverage,
                "Premium Amount": premium,
                "Deductible": deductible,
                "Occupation": occupation,
                "Geographic Information": geo,
                "Insurance Products Owned": products
            }

            # Preprocess and predict
            X_scaled = preprocess_input(input_data)
            pred_class = rf_model.predict(X_scaled)[0]
            pred_prob = rf_model.predict_proba(X_scaled)[0]
            risk_percentage = round(float(pred_prob[pred_class]) * 100, 2)
            risk_level = risk_map.get(pred_class, map)

            # Save prediction to DB first
            new_policy = Policy(
                user_id=current_user.id,
                income=income,
                coverage_amount=coverage,
                premium_amount=premium,
                deductible=deductible,
                occupation=occupation,
                geographic_info=geo,
                insurance_products=products,
                risk_score=risk_percentage,
                risk_level=risk_level,
               
                blockchain_txn=None
            )
            db.session.add(new_policy)
            db.session.commit()

            # -------------------------
            # Blockchain integration
            # -------------------------
            try:
                # Ensure the smart contract has a matching function
              
                txn = contract.functions.storePolicy(
                    int(risk_percentage), risk_level
                ).build_transaction({
                    'from': backend_account.address,
                    'nonce': w3.eth.get_transaction_count(backend_account.address),
                    'gas': 3000000,
                    'gasPrice': w3.to_wei('50', 'gwei')
                })

                # Sign the transaction using Web3.py v6+
                signed_txn = w3.eth.account.sign_transaction(txn, backend_private_key)

                # Send raw transaction
                tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

                # Wait for transaction receipt
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
                print(tx_receipt)
                # Save transaction hash in DB
                new_policy.blockchain_txn = tx_hash.hex()
                db.session.commit()
                print(f"Contract created: {new_policy.blockchain_txn}")

            except Exception as e:
                print("Blockchain error:", e)
                result = {"error": f"Prediction saved in DB, but blockchain error: {e}"}
                return render_template("predict.html", result=result)

            # Return results to frontend
            result = {
                "risk_level": risk_level,
                "risk_score": f"{risk_percentage}%",
                "blockchain_txn": new_policy.blockchain_txn
            }

        except Exception as e:
            db.session.rollback()
            print("Prediction error:", e)
            result = {"error": "Error in processing prediction."}

    return render_template("predict.html", result=result)




@app.route('/profile', methods=['GET'])
@login_required
def profile():
    if current_user.role != 'customer':
        flash("Admins do not have a profile page.", "warning")
        return redirect(url_for('login'))

    # Fetch user policies and bookings
    policies = Policy.query.filter_by(user_id=current_user.id).all()
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.booking_date.desc()).all()

    return render_template('profile.html', user=current_user, policies=policies, bookings=bookings)


@app.route('/view/policies', methods=['GET', 'POST'])
@login_required
def view_policies():
    if current_user.role != 'customer':
        flash("Please login access this page.", "warning")
        return redirect(url_for('login'))

    if request.method == "POST":
        policy_name = request.form.get("policy_name")

        # Create booking
        new_booking = Booking(
            user_id=current_user.id,
            user_name=current_user.username,
            policy_name=policy_name
        )
        db.session.add(new_booking)
        db.session.commit()
        flash(f"Policy '{policy_name}' booked successfully!", "success")
        return redirect(url_for('view_policies'))

    # Fetch all policies
    decb_entries = Decb.query.order_by(Decb.date.desc()).all()
    return render_template("view_policies.html", entries=decb_entries)


# @app.route('/company', methods=['GET', 'POST'])
# @login_required
# def company():
#     if current_user.role != 'customer':
#         flash("Please login to access this page.", "warning")
#         return redirect(url_for('login'))

#     step = session.get("company_step", "email")

#     if request.method == "POST":
#         print("Current step:", step, "Request method:", request.method)
#         # -------------------------
#         # Step 1: Phishing Acctack Verification
#         # -------------------------
#         if step == "email":
#             email = request.form.get("email")
#             if email != current_user.email:
#                 flash("Email does not match your account.", "danger")
#             else:
#                 otp = random.randint(100000, 999999)
#                 session["company_otp"] = str(otp)
#                 session["company_step"] = "otp"

#                 # Send OTP via SMTP
#                 try:
#                     sender_email = os.getenv("SENDER_EMAIL")
#                     sender_password = os.getenv("SENDER_PASSWORD")
#                     subject = "Your OTP for Company Verification"
#                     body = f"Hello {current_user.username},\n\nYour OTP is: {otp}\n\nThank you."

#                     msg = MIMEMultipart()
#                     msg['From'] = sender_email
#                     msg['To'] = email
#                     msg['Subject'] = subject
#                     msg.attach(MIMEText(body, 'plain'))

#                     server = smtplib.SMTP('smtp.gmail.com', 587)
#                     server.starttls()
#                     server.login(sender_email, sender_password)
#                     server.send_message(msg)
#                     server.quit()

#                     flash("OTP sent to your email.", "info")
#                 except Exception as e:
#                     flash(f"Failed to send OTP: {e}", "danger")
#             return redirect(url_for("company"))

#         # -------------------------
#         # Step 2: OTP verification
#         # -------------------------
#         elif step == "otp":
#             entered_otp = request.form.get("otp")
#             if entered_otp == session.get("company_otp"):
#                 flash("OTP verified successfully!", "success")
#                 session["company_step"] = "send_blockchain"
#             else:
#                 flash("Invalid OTP. Try again.", "danger")
#             return redirect(url_for("company"))
            


#         # -------------------------
#         # Step 3: Send company data to blockchain
#         # -------------------------
#         elif step == "send_blockchain":
#             company_name = request.form.get("company_name")
#             company_address = request.form.get("company_address")
#             document = request.files.get("document")
#             document = request.files.get("document")
#             print("Document object:", document)
#             print("Document filename:", document.filename if document else None)

#             print("send")

#             if document:
               
#                 # Convert document to hash
              
#                 file_bytes = document.read()
#                 document_hash = hashlib.sha256(file_bytes).hexdigest()
#                 print("phising")

#                 try:
#                     txn = contract.functions.storeCompany(
#                         company_name,
#                         company_address,
#                         document_hash
#                     ).build_transaction({
#                         'from': backend_account.address,
#                         'nonce': w3.eth.get_transaction_count(backend_account.address),
#                         'gas': 3000000,
#                         'gasPrice': w3.to_wei('50', 'gwei')
#                     })

#                     signed_txn = w3.eth.account.sign_transaction(txn, backend_private_key)
#                     tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
#                     w3.eth.wait_for_transaction_receipt(tx_hash)

#                     flash(f"Company data sent to blockchain successfully! Tx Hash: {tx_hash.hex()}", "success")

#                 except Exception as e:
#                     flash(f"Blockchain transaction  Failed Phising Detection : {e}", "danger")
#                     print("Blockchain error:", e)

#                 # Clear session steps
#                 session.pop("company_step", None)
#                 session.pop("company_otp", None)
#                 return redirect(url_for("company"))

#     return render_template("company.html", step=step)


# Add needed imports at top of your file (if not already present)
import os
import random
from sqlalchemy.exc import SQLAlchemyError
import re
import secrets
import json as _json
import hashlib
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import request, session, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

SQLI_PATTERNS = [
    r"(--|\bOR\b|\bAND\b).*(=|LIKE)|\bUNION\b|\bSELECT\b.*\bFROM\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b",
    r"['\"].*--",
    r";\s*DROP\s+TABLE",
]

def detect_sqli(payload: str) -> bool:
    if not payload:
        return False
    try:
        for pat in SQLI_PATTERNS:
            if re.search(pat, payload, flags=re.IGNORECASE):
                return True
    except Exception:
        return False
    # some common phrases
    p = payload.upper()
    if any(token in p for token in ["' OR '1'='1", "' OR 1=1", "UNION SELECT", "DROP TABLE"]):
        return True
    return False

def log_attack(user_id, attack_type, payload=None, ip=None, attempts=1, success=False, meta_data=None):
    try:
        ae = AttackEvent(
            user_id=user_id,
            attack_type=attack_type,
            payload=payload,
            ip_address=ip,
            attempts=attempts,
            success=success,
            meta_data=_json.dumps(meta_data) if meta_data else None
        )
        db.session.add(ae)
        db.session.commit()
        return ae
    except SQLAlchemyError as e:
        db.session.rollback()
        print("Failed to log attack:", e)
        return None

# constants / patterns
SUSPICIOUS_KEYWORDS = ["bank", "password", "otp", "click here", "login", "verify", "confirm", "urgent"]
URL_PATTERN = re.compile(r"https?://", flags=re.IGNORECASE)
TOKEN_HEX_PATTERN = re.compile(r'\b[0-9a-fA-F]{64}\b')

# Full route
@app.route('/company', methods=['GET', 'POST'])
@login_required
def company():
    # Only customers can access this page
    if current_user.role != 'customer':
        flash("Please login with a customer account to access this page.", "warning")
        return redirect(url_for('login'))

    # Step tracking
    step = session.get("company_step", "email")

    # If the step indicates 'otp' but we do not have an OTP value stored, reset to 'email'
    # This often happens when a client has leftover session data from a previous login, or after a logout
    if step == "otp" and not session.get("company_otp"):
        session['company_step'] = 'email'
        step = 'email'
        flash("OTP session missing or expired; please request a new OTP.", "warning")

    # If there's a phish_info stored from prior attempt, pass it to template
    phish_info = session.get("last_phish_info")

    if request.method == "POST":
        # Read step fresh (it may have been updated)
        step = session.get("company_step", "email")
        # Step 0: allow a "restart" or "force_send" action from template
        if request.form.get("action") == "restart":
            session.pop("company_step", None)
            session.pop("company_otp", None)
            session.pop("last_phish_info", None)
            return redirect(url_for('company'))

        # -------------------------
        # Step 1: Email verification -> send OTP
        # -------------------------
        if step == "email":
            email = (request.form.get("email") or "").strip()
            if email != current_user.email:
                flash("Email does not match your account.", "danger")
                return redirect(url_for("company"))
            # generate OTP and move to next step
            otp = random.randint(100000, 999999)
            session["company_otp"] = str(otp)
            session["company_step"] = "otp"

            # Send OTP via SMTP (development/testing). Use env vars for credentials.
            try:
                sender_email = os.getenv("SENDER_EMAIL")
                sender_password = os.getenv("SENDER_PASSWORD")
                subject = "Your OTP for Company Verification"
                body = f"Hello {current_user.username},\n\nYour OTP is: {otp}\n\nThank you."

                msg = MIMEMultipart()
                msg['From'] = sender_email if sender_email else 'no-reply@example.com'
                msg['To'] = email
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'plain'))

                # If SMTP credentials are missing, do not throw; log OTP for dev and inform user
                if not sender_email or not sender_password:
                    print("[DEBUG] SMTP credentials missing; OTP was not sent via email. OTP:", otp)
                    flash("OTP generated but email delivery failed (SMTP not configured). For development, the OTP is printed to server logs.", "warning")
                else:
                    server = smtplib.SMTP('smtp.gmail.com', 587)
                    server.starttls()
                    server.login(sender_email, sender_password)
                    server.send_message(msg)
                    server.quit()
                    flash("OTP sent to your email.", "info")
            except Exception as e:
                # Do not expose full exception in prod; it's useful for local testing
                print(f"[ERROR] OTP send failed: {e}")
                flash(f"Failed to send OTP: {e}", "danger")
            return redirect(url_for("company"))

        # -------------------------
        # Step 2: OTP verification
        # -------------------------
        elif step == "otp":
            entered_otp = (request.form.get("otp") or "").strip()
            if entered_otp == session.get("company_otp"):
                flash("OTP verified successfully!", "success")
                session["company_step"] = "send_blockchain"
            else:
                flash("Invalid OTP. Try again.", "danger")
            return redirect(url_for("company"))

        # -------------------------
        # Step 3: Send company data to blockchain (with phishing scan)
        # -------------------------
        elif step == "send_blockchain":
            # If user pressed a "force send" button, allow override (dangerous)
            force_send = bool(request.form.get("force_send"))

            company_name = (request.form.get("company_name") or "").strip()
            company_address = (request.form.get("company_address") or "").strip()
            document = request.files.get("document")  # Werkzeug FileStorage or None
            timestamp = datetime.utcnow().isoformat()

            # phish_info collects indicators
            phish_info = {
                "detected": False,
                "reasons": [],
                "document_hash": None,
                "document_filename": document.filename if document else None,
                "checked_at": timestamp
            }

          
            try:
                if detect_sqli(company_name) or detect_sqli(company_address):
                    phish_info["detected"] = True
                    phish_info["reasons"].append("Suspicious SQL-like pattern in company name/address")
            except Exception:
               
                pass

            combined_text = (company_name + " " + company_address).lower()
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in combined_text:
                    phish_info["detected"] = True
                    phish_info["reasons"].append(f"Suspicious keyword found in name/address: {kw}")

          
            if document:
              
                file_bytes = document.read()
                document_hash = hashlib.sha256(file_bytes).hexdigest()
                phish_info["document_hash"] = document_hash

              
                try:
                    document.stream.seek(0)
                except Exception:
                    pass

              
                try:
                    text = file_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    text = ""

                if TOKEN_HEX_PATTERN.search(text):
                    phish_info["detected"] = True
                    phish_info["reasons"].append("Token-like hex string found inside document")

                if URL_PATTERN.search(text):
                    phish_info["detected"] = True
                    phish_info["reasons"].append("URL(s) found inside document")

                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in text.lower():
                        phish_info["detected"] = True
                        phish_info["reasons"].append(f"Suspicious keyword in document: {kw}")

              
                try:
                    prev = AttackEvent.query.filter_by(payload=document_hash).first()
                    if prev:
                        phish_info["detected"] = True
                        phish_info["reasons"].append("Document hash matches previously logged malicious file")
                except Exception:
                    pass

           
            try:
                log_attack(
                    user_id=current_user.id,
                    attack_type="phish_check",
                    payload=f"company:{company_name}",
                    ip=request.remote_addr,
                    attempts=1,
                    success=not phish_info["detected"],
                    metadata={"phish_info": phish_info, "timestamp": timestamp}
                )
            except Exception as e:
              
                print("log_attack failed:", e)

            
            if phish_info["detected"] and not force_send:
                session["last_phish_info"] = phish_info
               
                flash("Potential phishing indicators found in your submission. Review details below.", "danger")
                return redirect(url_for("company"))

            
            try:
               
                final_hash = ""
                if document:
                
                    try:
                        file_bytes = document.read()
                       
                        if not file_bytes:
                            document.stream.seek(0)
                            file_bytes = document.read()
                    except Exception:
                        
                        file_bytes = b""

                    if file_bytes:
                        final_hash = hashlib.sha256(file_bytes).hexdigest()
                    else:
                        final_hash = phish_info.get("document_hash") or ""

             
                txn = contract.functions.storeCompany(
                    company_name,
                    company_address,
                    final_hash
                ).build_transaction({
                    'from': backend_account.address,
                    'nonce': w3.eth.get_transaction_count(backend_account.address),
                    'gas': 3000000,
                    'gasPrice': w3.to_wei('50', 'gwei')
                })

                signed_txn = w3.eth.account.sign_transaction(txn, backend_private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
               
                w3.eth.wait_for_transaction_receipt(tx_hash)

                flash(f"Company data sent to blockchain successfully! Tx Hash: {tx_hash.hex()}", "success")
            except Exception as e:
                flash(f"Blockchain transaction failed: {e}", "danger")
                print("Blockchain error:", e)

           
            session.pop("company_step", None)
            session.pop("company_otp", None)
            session.pop("last_phish_info", None)
            return redirect(url_for("company"))

    
    return render_template("company.html", step=step, phish_info=session.get("last_phish_info"))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Clear company upload flow state from session to avoid stale OTP step after logout
    session.pop('company_step', None)
    session.pop('company_otp', None)
    session.pop('last_phish_info', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/policies')
@login_required
def admin_policies():
    if not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
  
    else:
       
        policies = Policy.query.all()
    return render_template('admin_policies.html', policies=policies)


@app.route('/verify_kyc/<int:user_id>')
@login_required
def verify_kyc(user_id):
    if not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.kyc_verified = True
    db.session.commit()
    flash(f'KYC verified for {user.username}.', 'success')
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/policy', methods=["GET", "POST"])
@login_required
def admin_policy():
    if not current_user.is_admin():
     flash('Access denied.', 'danger')

    if request.method == "POST":
        account_policy = request.form.get("account_policy")
        policy_name = request.form.get("policy_name")
        description = request.form.get("description")
        start_risk = request.form.get("start_risk")
        end_risk = request.form.get("end_risk")

        # Basic validation
        if not account_policy or not policy_name or not start_risk or not end_risk:
            flash("Please fill all required fields.", "warning")
        else:
            try:
                start_risk = float(start_risk)
                end_risk = float(end_risk)

                new_entry = Decb(
                    account_policy=account_policy,
                    policy_name=policy_name,
                    description=description,
                    start_risk=start_risk,
                    end_risk=end_risk,
                    date=datetime.utcnow()
                )
                db.session.add(new_entry)
                db.session.commit()
                flash("Policy created successfully!", "success")
                return redirect(url_for("admin_policy"))
            except ValueError:
                flash("Start risk and End risk must be numbers.", "danger")


    decb_entries = Decb.query.order_by(Decb.date.desc()).all()
    return render_template("admin_policy.html", entries=decb_entries)






@app.route('/admin/chart', methods=['GET'])
def get_policies():
    policies = Policy.query.all()

  
    risk_counts = Counter([p.risk_level for p in policies])

    
    occupation_premiums = {}
    for p in policies:
        if p.occupation:
            occupation_premiums.setdefault(p.occupation, []).append(p.premium_amount)
    avg_premiums = {occ: sum(vals)/len(vals) for occ, vals in occupation_premiums.items()}

    
    geo_coverage = {}
    for p in policies:
        if p.geographic_info:
            geo_coverage[p.geographic_info] = geo_coverage.get(p.geographic_info, 0) + p.coverage_amount

    return render_template(
        'chart.html',
        risk_counts=risk_counts,
        avg_premiums=avg_premiums,
        geo_coverage=geo_coverage
    )
    
# -----------------------
# Initialize DB
# -----------------------
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
