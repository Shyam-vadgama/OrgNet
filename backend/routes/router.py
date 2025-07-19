from fastapi import APIRouter, HTTPException
from models.models import User, Organization
from db.config import db
from utils import hash_password, verify_password, create_token
from fastapi import status

router = APIRouter()

@router.post("/organization/register")
async def register_organization(org: Organization):
    existing = await db["organizations"].find_one({"org_code": org.org_code})
    if existing:
        raise HTTPException(status_code=400, detail="Organization code already exists")
    org_dict = org.dict()
    org_dict["id"] = str(org_dict["id"])
    await db["organizations"].insert_one(org_dict)
    return {"message": "Organization registered", "org_code": org.org_code}

@router.post("/register")
async def register_user(user: User):
    existing = await db["users"].find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    user_dict = user.dict()
    user_dict["id"] = str(user_dict["id"])
    user_dict["password"] = hash_password(user_dict["password"])
    await db["users"].insert_one(user_dict)
    return {"message": "User registered"}

@router.post("/employee/register")
async def register_employee(user: User):
    if user.role != "employee":
        raise HTTPException(status_code=400, detail="Role must be employee")

    existing = await db["users"].find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    if not user.org_code:
        raise HTTPException(status_code=400, detail="Organization code is required")

    org = await db["organizations"].find_one({"org_code": user.org_code})
    if not org:
        raise HTTPException(status_code=404, detail="Organization code not found")

    user_dict = user.dict()
    user_dict["id"] = str(user_dict["id"])
    user_dict["password"] = hash_password(user_dict["password"])
    await db["users"].insert_one(user_dict)
    return {"message": "Employee registered under valid organization"}

@router.post("/login")
async def login(data: dict):
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    user = await db["users"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user["role"] not in ["admin", "employee"]:
        raise HTTPException(status_code=403, detail="Only admin and employee can login here")
    # Create JWT token
    # Patch: org_id is not in user, so use org_code
    token = create_token(type('UserObj', (), {
        'id': user['id'],
        'role': user['role'],
        'org_id': user.get('org_code', None)
    })())
    return {
        "message": f"Login successful for {user['role']}",
        "role": user["role"],
        "email": user["email"],
        "access_token": token,
        "token_type": "bearer"
    }
