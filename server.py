"""
Bor-bi Tech by TransTech Solution - Backend API
"""
from fastapi import FastAPI, APIRouter, HTTPException, Header, Depends, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path
import os
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import uuid
import cloudinary
import cloudinary.uploader

from models import *
from utils import *

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
db_name = os.environ['DB_NAME']
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "pauledoux@protonmail.com")

app = FastAPI(title="Bor-bi Tech API", version="1.0.0")
api_router = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# AUTHENTIFICATION
# ============================================================================

@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    try:
        existing = None
        if user_data.email:
            existing = await db.users.find_one({"email": user_data.email})
        if not existing and user_data.phone:
            existing = await db.users.find_one({"phone": user_data.phone})
        if existing:
            raise HTTPException(status_code=400, detail="Utilisateur déjà existant")
        user = User(
            id=str(uuid.uuid4()),
            email=user_data.email,
            phone=user_data.phone,
            passwordHash=hash_password(user_data.password) if user_data.password else None,
            role=user_data.role
        )
        await db.users.insert_one(user.dict(by_alias=True, exclude_none=True))
        token = create_jwt_token(user.id, user.role.value, user.email, user.phone)
        await log_audit(db, user.id, user.email or user.phone or "unknown", "register", {"role": user.role.value})
        return {"message": "Inscription réussie", "token": token, "user": user.dict()}
    except Exception as e:
        logger.error(f"Erreur inscription: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    try:
        user = await db.users.find_one({
            "$or": [{"email": credentials.identifier}, {"phone": credentials.identifier}]
        })
        if not user:
            raise HTTPException(status_code=401, detail="Identifiants invalides")
        if not user.get("passwordHash"):
            raise HTTPException(status_code=401, detail="Mot de passe non configuré")
        if not verify_password(credentials.password, user["passwordHash"]):
            raise HTTPException(status_code=401, detail="Identifiants invalides")
        token = create_jwt_token(user["id"], user["role"], user.get("email"), user.get("phone"))
        await log_audit(db, user["id"], user.get("email") or user.get("phone"), "login")
        return {"message": "Connexion réussie", "token": token, "user": user}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur login: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# PRODUITS
# ============================================================================

def serialize_doc(doc):
    if doc is None: return None
    if isinstance(doc, list): return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        doc = dict(doc)
        if '_id' in doc: del doc['_id']
        return doc
    return doc

@api_router.get("/products/default")
async def get_default_products(category: Optional[str] = None, search: Optional[str] = None, limit: int = 100):
    try:
        query = {}
        if category: query["category"] = category
        if search: query["$or"] = [
            {"nameFr": {"$regex": search, "$options": "i"}},
            {"nameWolof": {"$regex": search, "$options": "i"}}
        ]
        products = await db.default_products.find(query).limit(limit).to_list(limit)
        return serialize_doc(products)
    except Exception as e:
        logger.error(f"Erreur récupération produits: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# UPLOAD IMAGES
# ============================================================================

@api_router.post("/upload-image")
async def upload_product_image(
    file: UploadFile = File(...),
    current_user: Dict = Depends(get_current_user)
):
    try:
        allowed_types = ["image/jpeg", "image/png", "image/webp"]
        if file.content_type not in allowed_types:
            raise HTTPException(status_code=400, detail="Type de fichier non autorisé")
        contents = await file.read()
        if len(contents) > 5 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Fichier trop volumineux (max 5 Mo)")
        result = cloudinary.uploader.upload(
            contents,
            folder="borbi_products",
            transformation={"width": 800, "height": 800, "crop": "limit"}
        )
        return {"url": result["secure_url"], "public_id": result["public_id"]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur upload image: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# HEALTH
# ============================================================================

@api_router.get("/")
async def root():
    return {"message": "Bienvenue sur Bor-bi Tech API", "version": "1.0.0"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
