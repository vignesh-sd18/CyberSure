import json as _json
import re
from datetime import datetime
from io import StringIO

from flask import request, send_file, jsonify, Blueprint
from flask_login import UserMixin, login_required, current_user
from sqlalchemy.exc import SQLAlchemyError

from models import db, User, AttackEvent

attacks_bp = Blueprint('attacks', __name__)

# -------------------------
# Helper:  SQLi pattern detector 
# -------------------------
SQLI_PATTERNS = [
    r"(--|\bOR\b|\bAND\b).*(=|LIKE)|\bUNION\b|\bSELECT\b.*\bFROM\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b",
    r"['\"].*--",
    r";\s*DROP\s+TABLE",
]

def detect_sqli(payload: str) -> bool:
    if not payload:
        return False
    p = payload.upper()
    for pat in SQLI_PATTERNS:
        if re.search(pat, payload, flags=re.IGNORECASE):
            return True
    if any(token in p for token in ["' OR '1'='1", "' OR 1=1", "UNION SELECT", "DROP TABLE"]):
        return True
    return False

# -------------------------
# Helper: record an attack event
# -------------------------
def log_attack(user_id, attack_type, payload=None, ip=None, attempts=1, success=False, metadata=None):
    try:
        ae = AttackEvent(
            user_id=user_id,
            attack_type=attack_type,
            payload=payload,
            ip_address=ip,
            attempts=attempts,
            success=success,
            metadata=_json.dumps(metadata) if metadata else None
        )
        db.session.add(ae)
        db.session.commit()
        return ae
    except SQLAlchemyError as e:
        db.session.rollback()
        print("Failed to log attack:", e)
        return None

# -------------------------
# 1) Brute Force simulation
# -------------------------
@attacks_bp.route('/simulate/bruteforce', methods=['POST'])
@login_required
def simulate_bruteforce():
    """
    POST JSON:
    { "target_email": "victim@example.com", "attempts": 50, "ip": "1.2.3.4" }
    Simulates repeated failed login attempts on `target_email`.
    """
    if not current_user.is_admin():
        return jsonify({"error": "admin only"}), 403

    data = request.get_json() or {}
    target_email = data.get("target_email")
    attempts = int(data.get("attempts", 20))
    ip = data.get("ip", request.remote_addr)

    target_user = User.query.filter_by(email=target_email).first()
    user_id = target_user.id if target_user else None

    # Log failed attempts
    for i in range(attempts):
        log_attack(
            user_id=user_id,
            attack_type="bruteforce",
            payload=f"failed_login_attempt_{i+1}",
            ip=ip,
            attempts=1,
            success=False,
            metadata={"attempt_index": i+1}
        )

    # Final "account locked" simulated event
    log_attack(
        user_id=user_id,
        attack_type="bruteforce",
        payload="account_locked_simulated",
        ip=ip,
        attempts=attempts,
        success=False,
        metadata={"locked": True}
    )

    return jsonify({"status": "bruteforce_simulated", "target": target_email, "attempts": attempts})

# -------------------------
# 2) SQL Injection simulation + detector
# -------------------------
@attacks_bp.route('/simulate/sqli', methods=['POST'])
@login_required
def simulate_sqli():
    """
    POST JSON:
    { "user_id": 1, "payload": "1' OR '1'='1", "ip": "1.2.3.4" }
    Logs the payload and flags it if our detector hits.
    """
    if not current_user.is_admin():
        return jsonify({"error": "admin only"}), 403

    data = request.get_json() or {}
    user_id = data.get("user_id")
    payload = data.get("payload", "")
    ip = data.get("ip", request.remote_addr)

    is_sqli = detect_sqli(payload)
    log_attack(
        user_id=user_id,
        attack_type="sqli",
        payload=payload,
        ip=ip,
        attempts=1,
        success=False,
        metadata={"detected": is_sqli}
    )

    return jsonify({"status": "sqli_logged", "detected": is_sqli})


