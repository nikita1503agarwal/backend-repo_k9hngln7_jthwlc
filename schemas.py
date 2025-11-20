from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal

# Core domain schemas
class User(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    email: EmailStr
    hashed_password: str
    role: Literal['user','admin'] = 'user'
    avatar_url: Optional[str] = None
    is_active: bool = True

class Service(BaseModel):
    title: str = Field(..., min_length=2, max_length=100)
    description: str = Field(..., min_length=10, max_length=1000)
    price: float = Field(..., ge=0)
    category: Optional[str] = None
    is_active: bool = True

class Order(BaseModel):
    user_id: str
    service_id: str
    status: Literal['pending','confirmed','in_progress','completed','cancelled'] = 'pending'
    notes: Optional[str] = None
    total: float = Field(..., ge=0)

class Event(BaseModel):
    user_id: Optional[str] = None
    event_type: Literal['view','click','order','login','logout','chat','pageview']
    metadata: dict = {}
    path: Optional[str] = None

class Project(BaseModel):
    name: str
    client: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []
    cover_url: Optional[str] = None
