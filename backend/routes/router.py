from fastapi import APIRouter, HTTPException, Depends, Body
from models.models import User, Organization, TokenResponse
from db.config import db
from utils import hash_password, verify_password, create_token, get_current_user, oauth2_scheme
from fastapi import status
from fastapi.security import OAuth2PasswordRequestForm

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

@router.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username
    password = form_data.password
    print(f"[DEBUG] Login attempt for email: {email}")
    if not email or not password:
        print("[DEBUG] Missing email or password")
        raise HTTPException(status_code=400, detail="Email and password required")
    user = await db["users"].find_one({"email": email})
    print(f"[DEBUG] User found: {user}")
    if not user:
        print("[DEBUG] User not found")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(password, user["password"]):
        print("[DEBUG] Password verification failed")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    print("[DEBUG] Password verification succeeded")
    if user["role"] not in ["admin", "employee"]:
        print("[DEBUG] Invalid role for login")
        raise HTTPException(status_code=403, detail="Only admin and employee can login here")
    # Create JWT token
    token = create_token(type('UserObj', (), {
        'id': user['id'],
        'role': user['role'],
        'org': user.get('org_code', None)
    })())
    print(f"[DEBUG] Token generated: {token}")
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        message=f"Login successful for {user['role']}",
        role=user["role"],
        email=user["email"]
    )

@router.put("/change-password")
async def change_password(
    data: dict = Body(...),
    current_user: dict = Depends(get_current_user)
):
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Old and new password required")
    user = await db["users"].find_one({"id": current_user["sub"]})
    if not user or not verify_password(old_password, user["password"]):
        raise HTTPException(status_code=401, detail="Old password is incorrect")
    hashed_new = hash_password(new_password)
    await db["users"].update_one({"id": current_user["sub"]}, {"$set": {"password": hashed_new}})
    return {"message": "Password changed successfully"}

@router.get("/admin/employees")
async def get_employees(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    if not org_code:
        raise HTTPException(status_code=400, detail="No organization found for admin")
    employees = await db["users"].find({"role": "employee", "org_code": org_code}).to_list(length=1000)
    cleaned_employees = []
    for emp in employees:
        emp.pop("password", None)
        if "_id" in emp:
            emp["_id"] = str(emp["_id"])
        cleaned_employees.append(emp)
    return {"employees": cleaned_employees}

# Keep the token endpoint for backward compatibility
@router.post("/token", response_model=TokenResponse)
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return await login(form_data)

