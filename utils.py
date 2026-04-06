import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import bcrypt
import jwt
from fastapi import HTTPException, Header, Depends

JWT_SECRET = os.getenv("JWT_SECRET", "borbi_tech_secret_key_2025")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 7
SECRET_KEY = os.getenv("SECRET_KEY", "borbi_tech_hash_secret_2025")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, role: str, email: Optional[str] = None, phone: Optional[str] = None) -> str:
    expiration = datetime.utcnow() + timedelta(days=JWT_EXPIRATION)
    payload = {"user_id": user_id, "role": role, "email": email, "phone": phone, "exp": expiration}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")

def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)

def hash_transaction(vendor_id: str, client_id: str, total_cents: int, date: datetime) -> str:
    data = f"{vendor_id}{client_id}{total_cents}{date.isoformat()}{SECRET_KEY}"
    return hashlib.sha256(data.encode()).hexdigest()

def calculate_platform_fee(amount_cents: int) -> int:
    fee_rate = float(os.getenv("PLATFORM_FEE_RATE", "0.5"))
    return int(amount_cents * fee_rate / 100)

async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Token d'authentification requis")
    try:
        token = authorization.replace("Bearer ", "")
        return decode_jwt_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Authentification échouée")

def format_sms_message(client_name: str, debt: int, language: str, time: str) -> str:
    debt_formatted = f"{debt / 100:.0f}"
    messages = {
        "fr": {"morning": f"Bonjour {client_name}, votre solde est de {debt_formatted} FCFA.", "evening": f"Bonsoir {client_name}, votre solde est de {debt_formatted} FCFA."},
        "wo": {"morning": f"Asalaa malekum {client_name}, sa dette mooy {debt_formatted} FCFA.", "evening": f"Jamm ngeen si {client_name}, sa dette mooy {debt_formatted} FCFA."},
        "ar": {"morning": f"صباح الخير {client_name}، رصيدك هو {debt_formatted} فرنك.", "evening": f"مساء الخير {client_name}، رصيدك هو {debt_formatted} فرنك."}
    }
    lang = language if language in messages else "fr"
    time_of_day = "evening" if time == "18:00" else "morning"
    return messages[lang][time_of_day]

async def log_audit(db, user_id: str, user_email: str, action: str, details: Optional[Dict] = None, ip: Optional[str] = None):
    from models import AuditLog
    audit_entry = AuditLog(userId=user_id, userEmail=user_email, action=action, details=details, ip=ip)
    await db.audit_logs.insert_one(audit_entry.dict(by_alias=True, exclude_none=True))
