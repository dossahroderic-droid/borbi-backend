"""
Utilitaires pour Bor-bi Tech by TransTech Solution
"""
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import bcrypt
import jwt
from fastapi import HTTPException, Header, Depends
from models import Role

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "borbi_tech_secret_key_2025")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 7  # days

# Hashing Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "borbi_tech_hash_secret_2025")

def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe contre son hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, role: str, email: Optional[str] = None, phone: Optional[str] = None) -> str:
    """Crée un token JWT"""
    expiration = datetime.utcnow() + timedelta(days=JWT_EXPIRATION)
    payload = {
        "user_id": user_id,
        "role": role,
        "email": email,
        "phone": phone,
        "exp": expiration
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str) -> Dict[str, Any]:
    """Décode un token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")

def generate_otp() -> str:
    """Génère un code OTP à 6 chiffres"""
    return str(secrets.randbelow(900000) + 100000)

def hash_transaction(vendor_id: str, client_id: str, total_cents: int, date: datetime) -> str:
    """Génère un hash SHA-256 pour une transaction"""
    data = f"{vendor_id}{client_id}{total_cents}{date.isoformat()}{SECRET_KEY}"
    return hashlib.sha256(data.encode()).hexdigest()

def calculate_platform_fee(amount_cents: int) -> int:
    """Calcule la commission de la plateforme"""
    fee_rate = float(os.getenv("PLATFORM_FEE_RATE", "0.5"))
    return int(amount_cents * fee_rate / 100)

def convert_currency(amount: int, from_currency: str, to_currency: str = "XOF") -> int:
    """Convertit une devise en FCFA (XOF)"""
    if from_currency == to_currency:
        return amount
    
    rates = {
        "USD": float(os.getenv("EXCHANGE_RATE_USD_XOF", "600")),
        "EUR": float(os.getenv("EXCHANGE_RATE_EUR_XOF", "655")),
        "XOF": 1.0
    }
    
    if from_currency not in rates:
        return amount
    
    return int(amount * rates[from_currency])

async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Middleware pour récupérer l'utilisateur courant depuis le token JWT"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Token d'authentification requis")
    
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_jwt_token(token)
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentification échouée")

async def require_role(required_roles: list, current_user: Dict = Depends(get_current_user)):
    """Vérifie que l'utilisateur a un des rôles requis"""
    if current_user.get("role") not in required_roles:
        raise HTTPException(status_code=403, detail="Accès refusé")
    return current_user

# SMS Utilities (simulated for now, ready for Twilio)
def format_sms_message(client_name: str, debt: int, language: str, time: str) -> str:
    """Formate un message SMS de relance dans la langue appropriée"""
    debt_formatted = f"{debt / 100:.0f}"
    
    messages = {
        "fr": {
            "morning": f"Bonjour {client_name}, votre solde en attente est de {debt_formatted} FCFA. Merci de régulariser. Cordialement.",
            "evening": f"Bonsoir {client_name}, votre solde en attente est de {debt_formatted} FCFA. Merci de régulariser. Cordialement."
        },
        "wo": {
            "morning": f"Asalaa malekum {client_name}, sa dette mooy {debt_formatted} FCFA. Jërëjëf defal ko.",
            "evening": f"Jamm ngeen si {client_name}, sa dette mooy {debt_formatted} FCFA. Jërëjëf defal ko."
        },
        "ar": {
            "morning": f"صباح الخير {client_name}، رصيدك المستحق هو {debt_formatted} فرنك. شكراً لتسويته.",
            "evening": f"مساء الخير {client_name}، رصيدك المستحق هو {debt_formatted} فرنك. شكراً لتسويته."
        }
    }
    
    lang = language if language in messages else "fr"
    time_of_day = "evening" if time == "18:00" else "morning"
    
    return messages[lang][time_of_day]

async def log_audit(db, user_id: str, user_email: str, action: str, details: Optional[Dict] = None, ip: Optional[str] = None):
    """Enregistre une action dans l'audit log"""
    from models import AuditLog
    audit_entry = AuditLog(
        userId=user_id,
        userEmail=user_email,
        action=action,
        details=details,
        ip=ip
    )
    await db.audit_logs.insert_one(audit_entry.dict(by_alias=True, exclude_none=True))
