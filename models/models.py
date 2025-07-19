from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from uuid import UUID, uuid4

class Organization(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    org_code: str

class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    email: EmailStr
    password: str
    role: str = "student"
    org_code: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    message: str
    role: str
    email: str
