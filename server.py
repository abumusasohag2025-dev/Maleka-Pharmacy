from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
import base64

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'maleka-pharmacy-secret-key-2025')
ALGORITHM = "HS256"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    role: str = "customer"  # customer or admin
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserInDB(User):
    hashed_password: str

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    price: float
    image: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    inventory: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProductCreate(BaseModel):
    name: str
    price: float
    image: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    inventory: int = 0

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    image: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    inventory: Optional[int] = None

class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    price: float

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str
    customer_name: str
    customer_email: str
    items: List[OrderItem]
    total: float
    status: str = "pending"  # pending, processing, completed, cancelled
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderCreate(BaseModel):
    items: List[OrderItem]
    total: float

class OrderStatusUpdate(BaseModel):
    status: str

class Prescription(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str
    customer_name: str
    customer_email: str
    image_data: str  # base64 encoded image
    status: str = "pending"  # pending, approved, rejected
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PrescriptionCreate(BaseModel):
    image_data: str
    notes: Optional[str] = None

class PrescriptionStatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = None

class HealthBlog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    image: Optional[str] = None
    author: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class HealthBlogCreate(BaseModel):
    title: str
    content: str
    image: Optional[str] = None
    author: str

class HealthBlogUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    image: Optional[str] = None

class UserRoleUpdate(BaseModel):
    role: str

# ==================== HELPER FUNCTIONS ====================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# ==================== STARTUP - CREATE DEFAULT ADMIN ====================

@app.on_event("startup")
async def create_default_admin():
    admin_email = "admin@malekapharmacy.store"
    existing_admin = await db.users.find_one({"email": admin_email})
    
    if not existing_admin:
        admin_user = UserInDB(
            id=str(uuid.uuid4()),
            email=admin_email,
            name="Admin",
            role="admin",
            hashed_password=hash_password("admin123"),
            created_at=datetime.now(timezone.utc)
        )
        doc = admin_user.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        await db.users.insert_one(doc)
        logger.info(f"Default admin created: {admin_email} / admin123")
    else:
        logger.info("Default admin already exists")

# ==================== AUTHENTICATION ROUTES ====================

@api_router.post("/auth/signup")
async def signup(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user (default role: customer)
    user = UserInDB(
        id=str(uuid.uuid4()),
        email=user_data.email,
        name=user_data.name,
        role="customer",
        hashed_password=hash_password(user_data.password),
        created_at=datetime.now(timezone.utc)
    )
    
    doc = user.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.users.insert_one(doc)
    
    # Create token
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    
    return {
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role
        }
    }

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    # Find user
    user = await db.users.find_one({"email": login_data.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create token
    token = create_access_token({"sub": user["id"], "email": user["email"], "role": user["role"]})
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"]
        }
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "name": current_user["name"],
        "role": current_user["role"]
    }

# ==================== PRODUCT ROUTES ====================

@api_router.get("/products", response_model=List[Product])
async def get_products():
    products = await db.products.find({}, {"_id": 0}).to_list(1000)
    for product in products:
        if isinstance(product.get('created_at'), str):
            product['created_at'] = datetime.fromisoformat(product['created_at'])
    return products

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    if isinstance(product.get('created_at'), str):
        product['created_at'] = datetime.fromisoformat(product['created_at'])
    return product

@api_router.post("/products", response_model=Product)
async def create_product(product_data: ProductCreate, admin_user: dict = Depends(get_admin_user)):
    product = Product(**product_data.model_dump())
    doc = product.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.products.insert_one(doc)
    return product

@api_router.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: str, product_data: ProductUpdate, admin_user: dict = Depends(get_admin_user)):
    existing_product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not existing_product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = {k: v for k, v in product_data.model_dump().items() if v is not None}
    if update_data:
        await db.products.update_one({"id": product_id}, {"$set": update_data})
    
    updated_product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if isinstance(updated_product.get('created_at'), str):
        updated_product['created_at'] = datetime.fromisoformat(updated_product['created_at'])
    return updated_product

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, admin_user: dict = Depends(get_admin_user)):
    result = await db.products.delete_one({"id": product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted successfully"}

# ==================== ORDER ROUTES ====================

@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate, current_user: dict = Depends(get_current_user)):
    order = Order(
        customer_id=current_user["id"],
        customer_name=current_user["name"],
        customer_email=current_user["email"],
        items=order_data.items,
        total=order_data.total,
        status="pending"
    )
    doc = order.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.orders.insert_one(doc)
    return order

@api_router.get("/orders/my", response_model=List[Order])
async def get_my_orders(current_user: dict = Depends(get_current_user)):
    orders = await db.orders.find({"customer_id": current_user["id"]}, {"_id": 0}).to_list(1000)
    for order in orders:
        if isinstance(order.get('created_at'), str):
            order['created_at'] = datetime.fromisoformat(order['created_at'])
    return orders

@api_router.get("/orders", response_model=List[Order])
async def get_all_orders(admin_user: dict = Depends(get_admin_user)):
    orders = await db.orders.find({}, {"_id": 0}).to_list(1000)
    for order in orders:
        if isinstance(order.get('created_at'), str):
            order['created_at'] = datetime.fromisoformat(order['created_at'])
    return orders

@api_router.put("/orders/{order_id}", response_model=Order)
async def update_order_status(order_id: str, status_data: OrderStatusUpdate, admin_user: dict = Depends(get_admin_user)):
    existing_order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not existing_order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    await db.orders.update_one({"id": order_id}, {"$set": {"status": status_data.status}})
    updated_order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if isinstance(updated_order.get('created_at'), str):
        updated_order['created_at'] = datetime.fromisoformat(updated_order['created_at'])
    return updated_order

# ==================== PRESCRIPTION ROUTES ====================

@api_router.post("/prescriptions", response_model=Prescription)
async def create_prescription(prescription_data: PrescriptionCreate, current_user: dict = Depends(get_current_user)):
    prescription = Prescription(
        customer_id=current_user["id"],
        customer_name=current_user["name"],
        customer_email=current_user["email"],
        image_data=prescription_data.image_data,
        notes=prescription_data.notes,
        status="pending"
    )
    doc = prescription.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.prescriptions.insert_one(doc)
    return prescription

@api_router.get("/prescriptions/my", response_model=List[Prescription])
async def get_my_prescriptions(current_user: dict = Depends(get_current_user)):
    prescriptions = await db.prescriptions.find({"customer_id": current_user["id"]}, {"_id": 0}).to_list(1000)
    for prescription in prescriptions:
        if isinstance(prescription.get('created_at'), str):
            prescription['created_at'] = datetime.fromisoformat(prescription['created_at'])
    return prescriptions

@api_router.get("/prescriptions", response_model=List[Prescription])
async def get_all_prescriptions(admin_user: dict = Depends(get_admin_user)):
    prescriptions = await db.prescriptions.find({}, {"_id": 0}).to_list(1000)
    for prescription in prescriptions:
        if isinstance(prescription.get('created_at'), str):
            prescription['created_at'] = datetime.fromisoformat(prescription['created_at'])
    return prescriptions

@api_router.put("/prescriptions/{prescription_id}", response_model=Prescription)
async def update_prescription_status(prescription_id: str, status_data: PrescriptionStatusUpdate, admin_user: dict = Depends(get_admin_user)):
    existing_prescription = await db.prescriptions.find_one({"id": prescription_id}, {"_id": 0})
    if not existing_prescription:
        raise HTTPException(status_code=404, detail="Prescription not found")
    
    update_data = {"status": status_data.status}
    if status_data.notes:
        update_data["notes"] = status_data.notes
    
    await db.prescriptions.update_one({"id": prescription_id}, {"$set": update_data})
    updated_prescription = await db.prescriptions.find_one({"id": prescription_id}, {"_id": 0})
    if isinstance(updated_prescription.get('created_at'), str):
        updated_prescription['created_at'] = datetime.fromisoformat(updated_prescription['created_at'])
    return updated_prescription

# ==================== HEALTH BLOG ROUTES ====================

@api_router.get("/blogs", response_model=List[HealthBlog])
async def get_blogs():
    blogs = await db.health_blogs.find({}, {"_id": 0}).to_list(1000)
    for blog in blogs:
        if isinstance(blog.get('created_at'), str):
            blog['created_at'] = datetime.fromisoformat(blog['created_at'])
    return blogs

@api_router.get("/blogs/{blog_id}", response_model=HealthBlog)
async def get_blog(blog_id: str):
    blog = await db.health_blogs.find_one({"id": blog_id}, {"_id": 0})
    if not blog:
        raise HTTPException(status_code=404, detail="Blog not found")
    if isinstance(blog.get('created_at'), str):
        blog['created_at'] = datetime.fromisoformat(blog['created_at'])
    return blog

@api_router.post("/blogs", response_model=HealthBlog)
async def create_blog(blog_data: HealthBlogCreate, admin_user: dict = Depends(get_admin_user)):
    blog = HealthBlog(**blog_data.model_dump())
    doc = blog.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.health_blogs.insert_one(doc)
    return blog

@api_router.put("/blogs/{blog_id}", response_model=HealthBlog)
async def update_blog(blog_id: str, blog_data: HealthBlogUpdate, admin_user: dict = Depends(get_admin_user)):
    existing_blog = await db.health_blogs.find_one({"id": blog_id}, {"_id": 0})
    if not existing_blog:
        raise HTTPException(status_code=404, detail="Blog not found")
    
    update_data = {k: v for k, v in blog_data.model_dump().items() if v is not None}
    if update_data:
        await db.health_blogs.update_one({"id": blog_id}, {"$set": update_data})
    
    updated_blog = await db.health_blogs.find_one({"id": blog_id}, {"_id": 0})
    if isinstance(updated_blog.get('created_at'), str):
        updated_blog['created_at'] = datetime.fromisoformat(updated_blog['created_at'])
    return updated_blog

@api_router.delete("/blogs/{blog_id}")
async def delete_blog(blog_id: str, admin_user: dict = Depends(get_admin_user)):
    result = await db.health_blogs.delete_one({"id": blog_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Blog not found")
    return {"message": "Blog deleted successfully"}

# ==================== USER MANAGEMENT ROUTES ====================

@api_router.get("/users", response_model=List[User])
async def get_users(admin_user: dict = Depends(get_admin_user)):
    users = await db.users.find({}, {"_id": 0, "hashed_password": 0}).to_list(1000)
    for user in users:
        if isinstance(user.get('created_at'), str):
            user['created_at'] = datetime.fromisoformat(user['created_at'])
    return users

@api_router.put("/users/{user_id}/role", response_model=User)
async def update_user_role(user_id: str, role_data: UserRoleUpdate, admin_user: dict = Depends(get_admin_user)):
    if role_data.role not in ["customer", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'customer' or 'admin'")
    
    existing_user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Complete the role update logic
    await db.users.update_one({"id": user_id}, {"$set": {"role": role_data.role}})
    
    updated_user = await db.users.find_one({"id": user_id}, {"_id": 0, "hashed_password": 0})
    if isinstance(updated_user.get('created_at'), str):
        updated_user['created_at'] = datetime.fromisoformat(updated_user['created_at'])
        
    return updated_user

# ==================== FINAL SETUP ====================

# Include the API router
app.include_router(api_router)

# Add CORS middleware to allow frontend access
app.add_middleware(
    CORSMiddleware,
    # Origins are pulled from the .env file, defaults to all (*) for development
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root path for health check
@app.get("/")
async def root():
    return {"message": "Maleka Pharmacy Backend API is running."}
