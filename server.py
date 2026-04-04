"""
Bor-bi Tech by TransTech Solution - Backend API
Application complète de gestion pour vendeurs et grossistes
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
import base64
import io
import cloudinary
import cloudinary.uploader

# Import des modèles et utilitaires
from models import *
from utils import *

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configuration MongoDB
mongo_url = os.environ['MONGO_URL']
db_name = os.environ['DB_NAME']
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# Configuration Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# Configuration
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "pauledoux@protonmail.com")

# Création de l'application
app = FastAPI(title="Bor-bi Tech API", version="1.0.0")
api_router = APIRouter(prefix="/api")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# ROUTES D'AUTHENTIFICATION
# ============================================================================

@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    """Inscription d'un nouvel utilisateur"""
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
        
        return {
            "message": "Inscription réussie",
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "phone": user.phone,
                "role": user.role
            }
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    """Connexion utilisateur"""
    try:
        user = await db.users.find_one({
            "$or": [
                {"email": credentials.identifier},
                {"phone": credentials.identifier}
            ]
        })
        
        if not user:
            raise HTTPException(status_code=401, detail="Identifiants invalides")
        
        if credentials.password:
            if not user.get("passwordHash"):
                raise HTTPException(status_code=401, detail="Mot de passe non configuré")
            if not verify_password(credentials.password, user["passwordHash"]):
                raise HTTPException(status_code=401, detail="Identifiants invalides")
        
        token = create_jwt_token(
            user["id"],
            user["role"],
            user.get("email"),
            user.get("phone")
        )
        
        await log_audit(db, user["id"], user.get("email") or user.get("phone"), "login")
        
        return {
            "message": "Connexion réussie",
            "token": token,
            "user": {
                "id": user["id"],
                "email": user.get("email"),
                "phone": user.get("phone"),
                "role": user["role"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la connexion: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/auth/request-otp")
async def request_otp(otp_request: OtpRequest):
    """Demande d'OTP par téléphone"""
    try:
        code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        otp = OtpCode(
            id=str(uuid.uuid4()),
            phone=otp_request.phone,
            code=code,
            expiresAt=expires_at
        )
        await db.otp_codes.insert_one(otp.dict(by_alias=True, exclude_none=True))
        
        logger.info(f"Code OTP généré pour {otp_request.phone}: {code}")
        
        return {
            "message": "Code OTP envoyé",
            "phone": otp_request.phone,
            "debug_code": code if os.getenv("DEBUG") else None
        }
    except Exception as e:
        logger.error(f"Erreur lors de la génération OTP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/auth/verify-otp")
async def verify_otp(otp_verify: OtpVerify):
    """Vérification de l'OTP et connexion"""
    try:
        otp = await db.otp_codes.find_one({
            "phone": otp_verify.phone,
            "code": otp_verify.code,
            "used": False
        })
        
        if not otp:
            raise HTTPException(status_code=401, detail="Code OTP invalide")
        
        if datetime.utcnow() > otp["expiresAt"]:
            raise HTTPException(status_code=401, detail="Code OTP expiré")
        
        await db.otp_codes.update_one(
            {"_id": otp["_id"]},
            {"$set": {"used": True}}
        )
        
        user = await db.users.find_one({"phone": otp_verify.phone})
        
        if not user:
            user_id = str(uuid.uuid4())
            new_user = User(
                id=user_id,
                phone=otp_verify.phone,
                role=Role.VENDOR
            )
            await db.users.insert_one(new_user.dict(by_alias=True, exclude_none=True))
            user = new_user.dict()
        
        token = create_jwt_token(
            user["id"],
            user["role"],
            user.get("email"),
            user.get("phone")
        )
        
        return {
            "message": "Connexion réussie",
            "token": token,
            "user": {
                "id": user["id"],
                "phone": user.get("phone"),
                "role": user["role"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la vérification OTP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES PROFIL VENDEUR/GROSSISTE
# ============================================================================

@api_router.post("/vendors/profile")
async def create_vendor_profile(
    vendor_data: VendorCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Créer ou mettre à jour le profil vendeur"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        existing = await db.vendors.find_one({"userId": current_user["user_id"]})
        
        if existing:
            await db.vendors.update_one(
                {"userId": current_user["user_id"]},
                {"$set": vendor_data.dict(exclude_none=True)}
            )
            vendor_id = existing["id"]
        else:
            vendor = Vendor(
                id=str(uuid.uuid4()),
                userId=current_user["user_id"],
                **vendor_data.dict()
            )
            await db.vendors.insert_one(vendor.dict(by_alias=True, exclude_none=True))
            vendor_id = vendor.id
        
        await log_audit(db, current_user["user_id"], current_user.get("email", ""), "create_vendor_profile")
        
        return {"message": "Profil vendeur créé/mis à jour", "vendorId": vendor_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création profil vendeur: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/wholesalers/profile")
async def create_wholesaler_profile(
    wholesaler_data: WholesalerCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Créer ou mettre à jour le profil grossiste"""
    try:
        if current_user.get("role") != "WHOLESALER":
            raise HTTPException(status_code=403, detail="Accès réservé aux grossistes")
        
        existing = await db.wholesalers.find_one({"userId": current_user["user_id"]})
        
        if existing:
            await db.wholesalers.update_one(
                {"userId": current_user["user_id"]},
                {"$set": wholesaler_data.dict(exclude_none=True)}
            )
            wholesaler_id = existing["id"]
        else:
            wholesaler = Wholesaler(
                id=str(uuid.uuid4()),
                userId=current_user["user_id"],
                **wholesaler_data.dict()
            )
            await db.wholesalers.insert_one(wholesaler.dict(by_alias=True, exclude_none=True))
            wholesaler_id = wholesaler.id
        
        await log_audit(db, current_user["user_id"], current_user.get("email", ""), "create_wholesaler_profile")
        
        return {"message": "Profil grossiste créé/mis à jour", "wholesalerId": wholesaler_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création profil grossiste: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/profile")
async def get_profile(current_user: Dict = Depends(get_current_user)):
    """Récupérer le profil complet de l'utilisateur connecté"""
    try:
        user = await db.users.find_one({"id": current_user["user_id"]})
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
        profile = {
            "id": user["id"],
            "email": user.get("email"),
            "phone": user.get("phone"),
            "role": user["role"]
        }
        
        if user["role"] == "VENDOR":
            vendor = await db.vendors.find_one({"userId": user["id"]})
            if vendor:
                profile["vendor"] = vendor
        elif user["role"] == "WHOLESALER":
            wholesaler = await db.wholesalers.find_one({"userId": user["id"]})
            if wholesaler:
                profile["wholesaler"] = wholesaler
        
        return profile
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération profil: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES PRODUITS
# ============================================================================

def serialize_doc(doc):
    """Convertir un document MongoDB en dict sérialisable"""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        doc = dict(doc)
        if '_id' in doc:
            del doc['_id']
        return doc
    return doc

@api_router.get("/products/default")
async def get_default_products(
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100
):
    """Récupérer les produits par défaut du catalogue"""
    try:
        query = {}
        if category:
            query["category"] = category
        if search:
            query["$or"] = [
                {"nameFr": {"$regex": search, "$options": "i"}},
                {"nameWolof": {"$regex": search, "$options": "i"}}
            ]
        
        products = await db.default_products.find(query).limit(limit).to_list(limit)
        return serialize_doc(products)
    except Exception as e:
        logger.error(f"Erreur récupération produits: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/products/categories")
async def get_categories():
    """Récupérer toutes les catégories de produits"""
    try:
        categories = await db.default_products.distinct("category")
        return {"categories": categories}
    except Exception as e:
        logger.error(f"Erreur récupération catégories: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES VENDEUR - GESTION CATALOGUE
# ============================================================================

@api_router.post("/vendors/products")
async def add_vendor_product(
    product_data: VendorProductCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Ajouter un produit au catalogue du vendeur"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            raise HTTPException(status_code=404, detail="Profil vendeur non trouvé")
        
        vendor_product = VendorProduct(
            id=str(uuid.uuid4()),
            vendorId=vendor["id"],
            **product_data.dict()
        )
        
        await db.vendor_products.insert_one(vendor_product.dict(by_alias=True, exclude_none=True))
        
        return {"message": "Produit ajouté au catalogue", "productId": vendor_product.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur ajout produit vendeur: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/vendors/products")
async def get_vendor_products(current_user: Dict = Depends(get_current_user)):
    """Récupérer tous les produits du vendeur"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            return []
        
        vendor_products = await db.vendor_products.find({"vendorId": vendor["id"]}).to_list(1000)
        
        enriched = []
        for vp in vendor_products:
            if vp["productType"] == "DefaultProduct":
                product = await db.default_products.find_one({"id": vp["productId"]})
            else:
                product = await db.custom_products.find_one({"id": vp["productId"]})
            
            if product:
                enriched.append({
                    **vp,
                    "productDetails": product
                })
        
        return enriched
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération produits vendeur: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/vendors/custom-products")
async def create_custom_product(
    product_data: CustomProductCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Créer un produit personnalisé"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            raise HTTPException(status_code=404, detail="Profil vendeur non trouvé")
        
        custom_product = CustomProduct(
            id=str(uuid.uuid4()),
            vendorId=vendor["id"],
            **product_data.dict()
        )
        
        await db.custom_products.insert_one(custom_product.dict(by_alias=True, exclude_none=True))
        
        return {"message": "Produit personnalisé créé", "productId": custom_product.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création produit personnalisé: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES VENDEUR - GESTION CLIENTS
# ============================================================================

@api_router.post("/vendors/clients")
async def create_client(
    client_data: ClientCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Créer un nouveau client"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            raise HTTPException(status_code=404, detail="Profil vendeur non trouvé")
        
        existing = await db.clients.find_one({
            "vendorId": vendor["id"],
            "phone": client_data.phone
        })
        if existing:
            raise HTTPException(status_code=400, detail="Client déjà existant")
        
        client = Client(
            id=str(uuid.uuid4()),
            vendorId=vendor["id"],
            **client_data.dict()
        )
        
        await db.clients.insert_one(client.dict(by_alias=True, exclude_none=True))
        
        return {"message": "Client créé", "clientId": client.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création client: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/vendors/clients")
async def get_clients(current_user: Dict = Depends(get_current_user)):
    """Récupérer tous les clients du vendeur"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            return []
        
        clients = await db.clients.find({"vendorId": vendor["id"]}).to_list(1000)
        return clients
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération clients: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES VENDEUR - TRANSACTIONS/VENTES
# ============================================================================

@api_router.post("/vendors/transactions")
async def create_transaction(
    transaction_data: TransactionCreate,
    request: Request,
    current_user: Dict = Depends(get_current_user)
):
    """Créer une nouvelle transaction de vente"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            raise HTTPException(status_code=404, detail="Profil vendeur non trouvé")
        
        total = sum(item.total for item in transaction_data.items)
        remaining = total - transaction_data.amountPaid
        
        if transaction_data.amountPaid >= total:
            payment_status = PaymentStatus.PAID
            remaining = 0
        elif transaction_data.amountPaid > 0:
            payment_status = PaymentStatus.PARTIAL
        else:
            payment_status = PaymentStatus.UNPAID
        
        platform_fee = calculate_platform_fee(total)
        tx_hash = hash_transaction(vendor["id"], transaction_data.clientId, total, datetime.utcnow())
        
        transaction = Transaction(
            id=str(uuid.uuid4()),
            vendorId=vendor["id"],
            clientId=transaction_data.clientId,
            items=[item.dict() for item in transaction_data.items],
            totalCents=total,
            paymentStatus=payment_status,
            amountPaid=transaction_data.amountPaid,
            remaining=remaining,
            platformFeeCents=platform_fee,
            hash=tx_hash,
            vendorIp=request.client.host if request.client else None
        )
        
        await db.transactions.insert_one(transaction.dict(by_alias=True, exclude_none=True))
        
        if remaining > 0:
            await db.clients.update_one(
                {"id": transaction_data.clientId},
                {"$inc": {"debtBalance": remaining}}
            )
        
        commission = PlatformCommission(
            id=str(uuid.uuid4()),
            transactionId=transaction.id,
            amountCents=platform_fee,
            type="SALE"
        )
        await db.platform_commissions.insert_one(commission.dict(by_alias=True, exclude_none=True))
        
        for item in transaction_data.items:
            await db.vendor_products.update_one(
                {
                    "vendorId": vendor["id"],
                    "productId": item.productId,
                    "productType": item.productType
                },
                {"$inc": {"stock": -item.quantity}}
            )
            
            stock_movement = StockMovement(
                id=str(uuid.uuid4()),
                vendorId=vendor["id"],
                productId=item.productId,
                productType=item.productType,
                quantityChange=-item.quantity,
                reason="sale",
                referenceId=transaction.id
            )
            await db.stock_movements.insert_one(stock_movement.dict(by_alias=True, exclude_none=True))
        
        return {
            "message": "Transaction créée",
            "transactionId": transaction.id,
            "total": total,
            "amountPaid": transaction_data.amountPaid,
            "remaining": remaining,
            "hash": tx_hash
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création transaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/vendors/transactions")
async def get_vendor_transactions(current_user: Dict = Depends(get_current_user)):
    """Récupérer toutes les transactions du vendeur"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            return []
        
        transactions = await db.transactions.find({"vendorId": vendor["id"]}).sort("createdAt", -1).to_list(1000)
        return transactions
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération transactions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES GROSSISTES
# ============================================================================

@api_router.get("/wholesalers")
async def get_wholesalers(featured_only: bool = False):
    """Récupérer la liste des grossistes"""
    try:
        query = {}
        if featured_only:
            query["featured"] = True
        
        wholesalers = await db.wholesalers.find(query).to_list(1000)
        return wholesalers
    except Exception as e:
        logger.error(f"Erreur récupération grossistes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/wholesalers/{wholesaler_id}/products")
async def get_wholesaler_products(wholesaler_id: str):
    """Récupérer les produits d'un grossiste"""
    try:
        products = await db.wholesaler_products.find({"wholesalerId": wholesaler_id}).to_list(1000)
        
        enriched = []
        for wp in products:
            if wp["productType"] == "DefaultProduct":
                product = await db.default_products.find_one({"id": wp["productId"]})
            else:
                product = await db.custom_products.find_one({"id": wp["productId"]})
            
            if product:
                enriched.append({
                    **wp,
                    "productDetails": product
                })
        
        return enriched
    except Exception as e:
        logger.error(f"Erreur récupération produits grossiste: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES COMMANDES (VENDEUR -> GROSSISTE)
# ============================================================================

@api_router.post("/orders")
async def create_order(
    order_data: OrderCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Créer une commande auprès d'un grossiste"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            raise HTTPException(status_code=404, detail="Profil vendeur non trouvé")
        
        total = sum(item.total for item in order_data.items)
        platform_fee = calculate_platform_fee(total)
        
        order = Order(
            id=str(uuid.uuid4()),
            wholesalerId=order_data.wholesalerId,
            vendorId=vendor["id"],
            items=[item.dict() for item in order_data.items],
            status=OrderStatus.PENDING,
            totalCents=total,
            platformFeeCents=platform_fee
        )
        
        await db.orders.insert_one(order.dict(by_alias=True, exclude_none=True))
        
        commission = PlatformCommission(
            id=str(uuid.uuid4()),
            orderId=order.id,
            amountCents=platform_fee,
            type="ORDER"
        )
        await db.platform_commissions.insert_one(commission.dict(by_alias=True, exclude_none=True))
        
        return {
            "message": "Commande créée",
            "orderId": order.id,
            "total": total,
            "status": "PENDING"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création commande: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/orders/vendor")
async def get_vendor_orders(current_user: Dict = Depends(get_current_user)):
    """Récupérer les commandes du vendeur"""
    try:
        if current_user.get("role") != "VENDOR":
            raise HTTPException(status_code=403, detail="Accès réservé aux vendeurs")
        
        vendor = await db.vendors.find_one({"userId": current_user["user_id"]})
        if not vendor:
            return []
        
        orders = await db.orders.find({"vendorId": vendor["id"]}).sort("createdAt", -1).to_list(1000)
        return orders
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération commandes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/orders/wholesaler")
async def get_wholesaler_orders(current_user: Dict = Depends(get_current_user)):
    """Récupérer les commandes reçues par le grossiste"""
    try:
        if current_user.get("role") != "WHOLESALER":
            raise HTTPException(status_code=403, detail="Accès réservé aux grossistes")
        
        wholesaler = await db.wholesalers.find_one({"userId": current_user["user_id"]})
        if not wholesaler:
            return []
        
        orders = await db.orders.find({"wholesalerId": wholesaler["id"]}).sort("createdAt", -1).to_list(1000)
        return orders
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération commandes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.patch("/orders/{order_id}/status")
async def update_order_status(
    order_id: str,
    status: OrderStatus,
    current_user: Dict = Depends(get_current_user)
):
    """Mettre à jour le statut d'une commande (grossiste uniquement)"""
    try:
        if current_user.get("role") != "WHOLESALER":
            raise HTTPException(status_code=403, detail="Accès réservé aux grossistes")
        
        wholesaler = await db.wholesalers.find_one({"userId": current_user["user_id"]})
        if not wholesaler:
            raise HTTPException(status_code=404, detail="Profil grossiste non trouvé")
        
        result = await db.orders.update_one(
            {
                "id": order_id,
                "wholesalerId": wholesaler["id"]
            },
            {
                "$set": {
                    "status": status.value,
                    "updatedAt": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Commande non trouvée")
        
        return {"message": "Statut mis à jour", "status": status.value}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur mise à jour statut commande: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES MESSAGERIE
# ============================================================================

@api_router.get("/messages/conversations")
async def get_conversations(current_user: Dict = Depends(get_current_user)):
    """Récupérer toutes les conversations de l'utilisateur"""
    try:
        if current_user["role"] == "VENDOR":
            profile = await db.vendors.find_one({"userId": current_user["user_id"]})
            sender_type = "vendor"
        else:
            profile = await db.wholesalers.find_one({"userId": current_user["user_id"]})
            sender_type = "wholesaler"
        
        if not profile:
            return []
        
        messages = await db.messages.find({
            "$or": [
                {"senderId": profile["id"]},
                {"receiverId": profile["id"]}
            ]
        }).sort("createdAt", -1).to_list(1000)
        
        conversations = {}
        for msg in messages:
            other_id = msg["receiverId"] if msg["senderId"] == profile["id"] else msg["senderId"]
            
            if other_id not in conversations:
                unread_count = await db.messages.count_documents({
                    "receiverId": profile["id"],
                    "senderId": other_id,
                    "read": False
                })
                
                conversations[other_id] = {
                    "participantId": other_id,
                    "participantType": msg["receiverType"] if msg["senderId"] == profile["id"] else msg["senderType"],
                    "lastMessage": msg,
                    "unreadCount": unread_count
                }
        
        return list(conversations.values())
    except Exception as e:
        logger.error(f"Erreur récupération conversations: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/messages/{user_id}")
async def get_messages_with_user(
    user_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Récupérer tous les messages avec un utilisateur spécifique"""
    try:
        if current_user["role"] == "VENDOR":
            profile = await db.vendors.find_one({"userId": current_user["user_id"]})
        else:
            profile = await db.wholesalers.find_one({"userId": current_user["user_id"]})
        
        if not profile:
            return []
        
        messages = await db.messages.find({
            "$or": [
                {"senderId": profile["id"], "receiverId": user_id},
                {"senderId": user_id, "receiverId": profile["id"]}
            ]
        }).sort("createdAt", 1).to_list(1000)
        
        await db.messages.update_many(
            {
                "receiverId": profile["id"],
                "senderId": user_id,
                "read": False
            },
            {"$set": {"read": True}}
        )
        
        return messages
    except Exception as e:
        logger.error(f"Erreur récupération messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/messages")
async def send_message(
    message_data: MessageCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Envoyer un message"""
    try:
        if current_user["role"] == "VENDOR":
            profile = await db.vendors.find_one({"userId": current_user["user_id"]})
            sender_type = "vendor"
        else:
            profile = await db.wholesalers.find_one({"userId": current_user["user_id"]})
            sender_type = "wholesaler"
        
        if not profile:
            raise HTTPException(status_code=404, detail="Profil non trouvé")
        
        message = Message(
            id=str(uuid.uuid4()),
            senderId=profile["id"],
            senderType=sender_type,
            receiverId=message_data.receiverId,
            receiverType=message_data.receiverType,
            content=message_data.content,
            orderId=message_data.orderId
        )
        
        await db.messages.insert_one(message.dict(by_alias=True, exclude_none=True))
        
        await log_audit(db, current_user["user_id"], current_user.get("email", ""), "send_message")
        
        return {"message": "Message envoyé", "messageId": message.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur envoi message: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES UPLOAD IMAGES (CLOUDINARY)
# ============================================================================

@api_router.post("/upload")
async def upload_image(
    file: UploadFile = File(...),
    current_user: Dict = Depends(get_current_user)
):
    """Upload une image vers Cloudinary"""
    try:
        contents = await file.read()
        
        result = cloudinary.uploader.upload(
            contents,
            folder="borbi_products",
            transformation={"width": 800, "height": 800, "crop": "limit"}
        )
        
        return {
            "url": result["secure_url"],
            "public_id": result["public_id"]
        }
    except Exception as e:
        logger.error(f"Erreur upload image: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES PUBLIQUES (PAGE D'ACCUEIL)
# ============================================================================

@api_router.get("/public/homepage")
async def get_homepage_products():
    """Récupérer les produits sponsorisés pour la page d'accueil"""
    try:
        now = datetime.utcnow()
        sponsored = await db.sponsored_products.find({
            "active": True,
            "startDate": {"$lte": now},
            "endDate": {"$gte": now}
        }).sort("homepageOrder", 1).limit(50).to_list(50)
        
        products = []
        for sp in sponsored:
            product = await db.default_products.find_one({"id": sp["defaultProductId"]})
            if product:
                products.append({
                    "sponsoredId": sp["id"],
                    "product": product,
                    "order": sp.get("homepageOrder", 999)
                })
        
        return products
    except Exception as e:
        logger.error(f"Erreur récupération produits homepage: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTES ADMIN
# ============================================================================

@api_router.get("/admin/dashboard")
async def get_admin_dashboard(current_user: Dict = Depends(get_current_user)):
    """Récupérer les statistiques pour le tableau de bord admin"""
    try:
        if current_user.get("email") != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Accès réservé à l'administrateur")
        
        total_users = await db.users.count_documents({})
        total_vendors = await db.vendors.count_documents({})
        total_wholesalers = await db.wholesalers.count_documents({})
        total_transactions = await db.transactions.count_documents({})
        total_orders = await db.orders.count_documents({})
        
        commissions = await db.platform_commissions.find({}).to_list(10000)
        total_commissions = sum(c["amountCents"] for c in commissions)
        pending_commissions = sum(c["amountCents"] for c in commissions if c["status"] == "PENDING")
        
        return {
            "users": {
                "total": total_users,
                "vendors": total_vendors,
                "wholesalers": total_wholesalers
            },
            "transactions": {
                "total": total_transactions,
                "orders": total_orders
            },
            "commissions": {
                "total": total_commissions / 100,
                "pending": pending_commissions / 100
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur dashboard admin: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/admin/users")
async def get_all_users(current_user: Dict = Depends(get_current_user)):
    """Récupérer tous les utilisateurs"""
    try:
        if current_user.get("email") != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Accès réservé à l'administrateur")
        
        users = await db.users.find({}).to_list(10000)
        return users
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération utilisateurs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/admin/sponsored-products")
async def create_sponsored_product(
    sponsored_data: SponsoredProductCreate,
    current_user: Dict = Depends(get_current_user)
):
    """Créer un produit sponsorisé"""
    try:
        if current_user.get("email") != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Accès réservé à l'administrateur")
        
        sponsored = SponsoredProduct(
            id=str(uuid.uuid4()),
            **sponsored_data.dict()
        )
        
        await db.sponsored_products.insert_one(sponsored.dict(by_alias=True, exclude_none=True))
        
        return {"message": "Produit sponsorisé créé", "sponsoredId": sponsored.id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur création produit sponsorisé: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ROUTE RACINE & HEALTH CHECK
# ============================================================================

@api_router.get("/")
async def root():
    return {
        "message": "Bienvenue sur Bor-bi Tech API by TransTech Solution",
        "version": "1.0.0",
        "status": "operational"
    }

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Inclure le router dans l'app
app.include_router(api_router)

# Shutdown handler
@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
