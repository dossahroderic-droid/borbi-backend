"""
Modèles de données pour Bor-bi Tech by TransTech Solution
Tous les montants sont en cents (FCFA)
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class Role(str, Enum):
    ADMIN = "ADMIN"
    VENDOR = "VENDOR"
    WHOLESALER = "WHOLESALER"

class PaymentStatus(str, Enum):
    PAID = "PAID"
    PARTIAL = "PARTIAL"
    UNPAID = "UNPAID"

class OrderStatus(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    DELIVERED = "DELIVERED"
    CANCELLED = "CANCELLED"

class CommissionStatus(str, Enum):
    PENDING = "PENDING"
    COLLECTED = "COLLECTED"

class InvoiceStatus(str, Enum):
    UNPAID = "UNPAID"
    PAID = "PAID"

# User Models
class User(BaseModel):
    id: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    passwordHash: Optional[str] = None
    role: Role
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    role: Role

class UserLogin(BaseModel):
    identifier: str  # email or phone
    password: Optional[str] = None

# Vendor Models
class Vendor(BaseModel):
    id: Optional[str] = None
    userId: str
    businessName: str
    phone: str
    location: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class VendorCreate(BaseModel):
    businessName: str
    phone: str
    location: Optional[str] = None

# Wholesaler Models
class Wholesaler(BaseModel):
    id: Optional[str] = None
    userId: str
    businessName: str
    phone: str
    location: Optional[str] = None
    currency: str = "XOF"
    featured: bool = False
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class WholesalerCreate(BaseModel):
    businessName: str
    phone: str
    location: Optional[str] = None
    currency: str = "XOF"

# Client Models
class Client(BaseModel):
    id: Optional[str] = None
    vendorId: str
    name: str
    phone: str
    email: Optional[EmailStr] = None
    debtBalance: int = 0  # en cents
    preferredLanguage: str = "fr"
    consentGiven: bool = False
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class ClientCreate(BaseModel):
    name: str
    phone: str
    email: Optional[EmailStr] = None
    preferredLanguage: str = "fr"
    consentGiven: bool = False

# Product Models
class DefaultProduct(BaseModel):
    id: Optional[str] = None
    nameFr: str
    nameWolof: str
    category: str
    unit: str
    defaultPrice: int  # cents
    imageUrl: Optional[str] = None
    brand: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class CustomProduct(BaseModel):
    id: Optional[str] = None
    vendorId: Optional[str] = None
    wholesalerId: Optional[str] = None
    name: str
    nameWolof: Optional[str] = None
    unit: str
    price: int  # cents
    stock: int = 0
    imageUrl: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

class CustomProductCreate(BaseModel):
    name: str
    nameWolof: Optional[str] = None
    unit: str
    price: int
    stock: int = 0
    imageUrl: Optional[str] = None

# VendorProduct Models
class VendorProduct(BaseModel):
    id: Optional[str] = None
    vendorId: str
    productId: str
    productType: str  # "DefaultProduct" or "CustomProduct"
    price: int  # cents
    stock: int = 0
    lowStockAlert: int = 5
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

class VendorProductCreate(BaseModel):
    productId: str
    productType: str
    price: int
    stock: int = 0
    lowStockAlert: int = 5

# WholesalerProduct Models
class WholesalerProduct(BaseModel):
    id: Optional[str] = None
    wholesalerId: str
    productId: str
    productType: str
    price: int  # cents (converted to XOF)
    originalPrice: Optional[int] = None
    currency: str = "XOF"
    conditioning: str  # ex: "carton 24", "sac 50kg"
    stock: int = 0
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

class WholesalerProductCreate(BaseModel):
    productId: str
    productType: str
    price: int
    originalPrice: Optional[int] = None
    currency: str = "XOF"
    conditioning: str
    stock: int = 0

# Transaction Models
class TransactionItem(BaseModel):
    productId: str
    productType: str
    productName: str
    quantity: int
    unitPrice: int
    total: int

class Transaction(BaseModel):
    id: Optional[str] = None
    vendorId: str
    clientId: str
    items: List[Dict[str, Any]]
    totalCents: int
    paymentStatus: PaymentStatus
    amountPaid: int = 0
    remaining: int = 0
    platformFeeCents: int = 0
    hash: str
    vendorIp: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class TransactionCreate(BaseModel):
    clientId: str
    items: List[TransactionItem]
    amountPaid: int = 0

# Payment Models
class Payment(BaseModel):
    id: Optional[str] = None
    transactionId: str
    amountCents: int
    previousDebt: int
    newDebt: int
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class PaymentCreate(BaseModel):
    transactionId: str
    amountCents: int

# Order Models
class OrderItem(BaseModel):
    productId: str
    productType: str
    productName: str
    conditioning: str
    quantity: int
    unitPrice: int
    total: int

class Order(BaseModel):
    id: Optional[str] = None
    wholesalerId: str
    vendorId: str
    items: List[Dict[str, Any]]
    status: OrderStatus
    totalCents: int
    platformFeeCents: int = 0
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

class OrderCreate(BaseModel):
    wholesalerId: str
    items: List[OrderItem]

# Message Models
class Message(BaseModel):
    id: Optional[str] = None
    senderId: str
    senderType: str  # "vendor" or "wholesaler"
    receiverId: str
    receiverType: str
    content: str
    read: bool = False
    orderId: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class MessageCreate(BaseModel):
    receiverId: str
    receiverType: str
    content: str
    orderId: Optional[str] = None

# SMS Models
class SmsLog(BaseModel):
    id: Optional[str] = None
    clientId: str
    phone: str
    message: str
    language: str
    status: str
    sentAt: datetime = Field(default_factory=datetime.utcnow)

# OTP Models
class OtpCode(BaseModel):
    id: Optional[str] = None
    phone: str
    code: str
    expiresAt: datetime
    used: bool = False
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class OtpRequest(BaseModel):
    phone: str

class OtpVerify(BaseModel):
    phone: str
    code: str

# StockMovement Models
class StockMovement(BaseModel):
    id: Optional[str] = None
    vendorId: str
    productId: str
    productType: str
    quantityChange: int
    reason: str  # "sale", "restock", "adjustment", "return"
    referenceId: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

# ChatMessage Models
class ChatMessage(BaseModel):
    id: Optional[str] = None
    userId: str
    userRole: str
    question: str
    answer: str
    language: str
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class ChatRequest(BaseModel):
    question: str
    language: str = "fr"

# PlatformCommission Models
class PlatformCommission(BaseModel):
    id: Optional[str] = None
    transactionId: Optional[str] = None
    orderId: Optional[str] = None
    amountCents: int
    type: str  # "SALE" or "ORDER"
    status: CommissionStatus = CommissionStatus.PENDING
    collectedAt: Optional[datetime] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

# Invoice Models
class Invoice(BaseModel):
    id: Optional[str] = None
    vendorId: Optional[str] = None
    wholesalerId: Optional[str] = None
    month: datetime
    totalCents: int
    status: InvoiceStatus = InvoiceStatus.UNPAID
    paidAt: Optional[datetime] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

# SponsoredProduct Models
class SponsoredProduct(BaseModel):
    id: Optional[str] = None
    defaultProductId: str
    startDate: datetime
    endDate: datetime
    active: bool = True
    homepageOrder: Optional[int] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class SponsoredProductCreate(BaseModel):
    defaultProductId: str
    startDate: datetime
    endDate: datetime
    homepageOrder: Optional[int] = None

# DataSubscription Models
class DataSubscription(BaseModel):
    id: Optional[str] = None
    companyName: str
    contactEmail: EmailStr
    startDate: datetime
    endDate: datetime
    monthlyFee: int
    active: bool = True
    createdAt: datetime = Field(default_factory=datetime.utcnow)

# AuditLog Models
class AuditLog(BaseModel):
    id: Optional[str] = None
    userId: str
    userEmail: str
    action: str
    details: Optional[Dict[str, Any]] = None
    ip: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)

# Voice/Whisper Models
class VoiceTranscription(BaseModel):
    audioData: str  # base64 encoded audio

class VoiceResponse(BaseModel):
    transcription: str
    parsed: Optional[Dict[str, Any]] = None
