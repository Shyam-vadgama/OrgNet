from pydantic import BaseModel
from enum import Enum
from typing import Optional

class UserRole(str, Enum):
    admin = "admin"
    student = "student"
    employee = "employee"

class AdminSchema(BaseModel):
    email: str
    password: str
    org_name: str

class UserRegisterSchema(BaseModel):
    email: str
    password: str
    role: UserRole
    org_code: str

class EmployeeUpdateSchema(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[UserRole] = None