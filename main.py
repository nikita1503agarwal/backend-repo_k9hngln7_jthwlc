import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal, Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User as UserSchema, Service as ServiceSchema, Order as OrderSchema, Event as EventSchema, Project as ProjectSchema

# App setup
app = FastAPI(title="SomDev Solutions API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Utilities
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    email: Optional[str] = None

class RegisterPayload(BaseModel):
    name: str
    email: EmailStr
    password: str

class ChatPayload(BaseModel):
    message: str
    context: Optional[dict] = None

class ServiceIn(BaseModel):
    title: str
    description: str
    price: float
    category: Optional[str] = None
    is_active: bool = True

class ProjectIn(BaseModel):
    name: str
    client: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []
    cover_url: Optional[str] = None

class OrderIn(BaseModel):
    service_id: str
    notes: Optional[str] = None
    total: float

class EventIn(BaseModel):
    event_type: Literal['view','click','order','login','logout','chat','pageview']
    metadata: dict = {}
    path: Optional[str] = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email}) if db else None


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_active", True):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_admin_user(current_user: dict = Depends(get_current_active_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


# Public endpoints
@app.get("/", tags=["meta"]) 
def read_root():
    return {"message": "SomDev Solutions API running"}

@app.get("/test", tags=["meta"]) 
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set"
            response["database_name"] = getattr(db, 'name', 'unknown')
            collections = db.list_collection_names()
            response["collections"] = collections
            response["connection_status"] = "Connected"
        return response
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
        return response


@app.get("/services", tags=["public"])
def list_services() -> List[dict]:
    docs = get_documents("service", {"is_active": True}) if db else []
    for d in docs:
        d["_id"] = str(d["_id"]) 
    return docs

@app.get("/projects", tags=["public"])
def list_projects() -> List[dict]:
    docs = get_documents("project", {}) if db else []
    for d in docs:
        d["_id"] = str(d["_id"]) 
    return docs


# Authentication
@app.post("/auth/register", response_model=Token, tags=["auth"]) 
def register(payload: RegisterPayload):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(payload.password)
    user_doc = UserSchema(name=payload.name, email=payload.email, hashed_password=hashed_password, role="user")
    create_document("user", user_doc)
    access_token = create_access_token(data={"sub": payload.email})
    return Token(access_token=access_token)

@app.post("/auth/login", response_model=Token, tags=["auth"]) 
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user["email"]})
    return Token(access_token=access_token)

@app.get("/me", tags=["auth"]) 
def me(current_user: dict = Depends(get_current_active_user)):
    user = current_user.copy()
    user["_id"] = str(user["_id"]) 
    user.pop("hashed_password", None)
    return user


# Orders (user)
@app.post("/orders", tags=["orders"]) 
def create_order(body: OrderIn, current_user: dict = Depends(get_current_active_user)):
    order = OrderSchema(user_id=str(current_user["_id"]), service_id=body.service_id, notes=body.notes, total=body.total)
    inserted_id = create_document("order", order)
    # Track event
    create_document("event", EventSchema(user_id=str(current_user["_id"]), event_type="order", metadata={"order_id": inserted_id}))
    return {"order_id": inserted_id, "status": "pending"}

@app.get("/orders", tags=["orders"]) 
def list_my_orders(current_user: dict = Depends(get_current_active_user)):
    orders = list(db["order"].find({"user_id": str(current_user["_id"])})) if db else []
    for o in orders:
        o["_id"] = str(o["_id"]) 
    return orders


# Activity tracking
@app.post("/events", tags=["analytics"]) 
def track_event(evt: EventIn, current_user: Optional[dict] = Depends(lambda: None)):
    try:
        user_id = str(current_user["_id"]) if current_user else None
    except Exception:
        user_id = None
    event_doc = EventSchema(user_id=user_id, event_type=evt.event_type, metadata=evt.metadata, path=evt.path)
    event_id = create_document("event", event_doc)
    return {"event_id": event_id}


# Admin endpoints
@app.get("/admin/overview", tags=["admin"]) 
def admin_overview(_: dict = Depends(get_admin_user)):
    counts = {
        "users": db["user"].count_documents({}),
        "services": db["service"].count_documents({}),
        "orders": db["order"].count_documents({}),
        "events": db["event"].count_documents({}),
        "projects": db["project"].count_documents({}),
    }
    return counts

@app.post("/admin/services", tags=["admin"]) 
def admin_create_service(body: ServiceIn, _: dict = Depends(get_admin_user)):
    sid = create_document("service", ServiceSchema(**body.model_dump()))
    return {"service_id": sid}

@app.put("/admin/services/{service_id}", tags=["admin"]) 
def admin_update_service(service_id: str, body: ServiceIn, _: dict = Depends(get_admin_user)):
    res = db["service"].update_one({"_id": db.client.get_default_database().client.get_default_database().decode_object_id(service_id) if False else {"$where": "ObjectId('" + service_id + "')"}}, {"$set": body.model_dump()})
    # Fallback simple update using string id handling
    try:
        from bson import ObjectId  # type: ignore
        res = db["service"].update_one({"_id": ObjectId(service_id)}, {"$set": body.model_dump()})
    except Exception:
        res = None
    return {"updated": bool(res and res.modified_count)}

@app.delete("/admin/services/{service_id}", tags=["admin"]) 
def admin_delete_service(service_id: str, _: dict = Depends(get_admin_user)):
    try:
        from bson import ObjectId  # type: ignore
        res = db["service"].delete_one({"_id": ObjectId(service_id)})
        return {"deleted": bool(res.deleted_count)}
    except Exception:
        return {"deleted": False}

@app.post("/admin/projects", tags=["admin"]) 
def admin_create_project(body: ProjectIn, _: dict = Depends(get_admin_user)):
    pid = create_document("project", ProjectSchema(**body.model_dump()))
    return {"project_id": pid}

@app.get("/admin/users", tags=["admin"]) 
def admin_list_users(_: dict = Depends(get_admin_user)):
    users = list(db["user"].find({})) if db else []
    for u in users:
        u["_id"] = str(u["_id"]) 
        u.pop("hashed_password", None)
    return users

@app.get("/admin/orders", tags=["admin"]) 
def admin_list_orders(_: dict = Depends(get_admin_user)):
    orders = list(db["order"].find({})) if db else []
    for o in orders:
        o["_id"] = str(o["_id"]) 
    return orders

@app.get("/admin/events", tags=["admin"]) 
def admin_list_events(limit: int = 200, _: dict = Depends(get_admin_user)):
    events = list(db["event"].find({}).sort("created_at", -1).limit(limit)) if db else []
    for e in events:
        e["_id"] = str(e["_id"]) 
    return events


# Chatbot (simple rule-based)
@app.post("/chatbot/ask", tags=["chat"])
def chatbot_ask(body: ChatPayload, current_user: Optional[dict] = Depends(lambda: None)):
    q = body.message.lower().strip()
    answer = ""
    if any(k in q for k in ["price", "cost", "pricing"]):
        answer = "Our services are priced transparently per project. Explore Services for exact pricing."
    elif any(k in q for k in ["service", "offer", "capability"]):
        services = [s.get("title") for s in get_documents("service")[:5]] if db else []
        answer = "We offer: " + ", ".join(services) if services else "We offer web, mobile, and cloud solutions tailored to your needs."
    elif any(k in q for k in ["order", "purchase", "buy"]):
        answer = "To place an order, open a service and click Order. You'll get confirmation immediately."
    elif any(k in q for k in ["contact", "email", "reach"]):
        answer = "You can reach us via the contact form; we typically reply within one business day."
    else:
        answer = "I can help with services, pricing, orders, and contact info. What would you like to know?"

    # track chat event
    try:
        uid = str(current_user["_id"]) if current_user else None
    except Exception:
        uid = None
    create_document("event", EventSchema(user_id=uid, event_type="chat", metadata={"q": q}))

    return {"reply": answer}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
