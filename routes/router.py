import os
from fastapi import APIRouter, HTTPException, Depends, Body, UploadFile, File
from models.models import User, Organization, TokenResponse
from db.config import db
from utils import hash_password, verify_password, create_token, get_current_user, oauth2_scheme, encrypt_bytes, decrypt_bytes, send_email_otp, create_otp_record, verify_otp
from fastapi import status
from fastapi.security import OAuth2PasswordRequestForm
from schemas.schemas import EmployeeUpdateSchema
from bson import ObjectId
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional
import io
from uuid import uuid4
from dotenv import load_dotenv
load_dotenv()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '../docs_uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

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

@router.post("/send-otp")
async def send_otp_for_registration(data: dict):
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    # Check if user already exists
    existing_user = await db["users"].find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create and store OTP
    otp_record = create_otp_record(email, "registration")
    await db["otps"].insert_one(otp_record)
    
    # Send OTP via email
    if send_email_otp(email, otp_record["otp"], "Email Verification OTP"):
        return {"message": "OTP sent to your email"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send OTP")

@router.post("/verify-otp-and-register")
async def verify_otp_and_register(data: dict):
    email = data.get("email")
    otp = data.get("otp")
    name = data.get("name")
    password = data.get("password")
    role = data.get("role", "student")
    org_code = data.get("org_code")
    
    if not all([email, otp, name, password]):
        raise HTTPException(status_code=400, detail="Email, OTP, name, and password required")
    
    # Verify OTP
    if not await verify_otp(email, otp, "registration"):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # Check if user already exists
    existing_user = await db["users"].find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    user_dict = {
        "id": str(uuid4()),
        "name": name,
        "email": email,
        "password": hash_password(password),
        "role": role,
        "org_code": org_code,
        "status": "active" if role != "employee" else "pending"
    }
    
    await db["users"].insert_one(user_dict)
    return {"message": "User registered successfully"}

@router.post("/send-password-reset-otp")
async def send_password_reset_otp(data: dict):
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    # Check if user exists
    user = await db["users"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Create and store OTP
    otp_record = create_otp_record(email, "password_reset")
    await db["otps"].insert_one(otp_record)
    
    # Send OTP via email
    if send_email_otp(email, otp_record["otp"], "Password Reset OTP"):
        return {"message": "Password reset OTP sent to your email"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send OTP")

@router.post("/reset-password-with-otp")
async def reset_password_with_otp(data: dict):
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("new_password")
    
    if not all([email, otp, new_password]):
        raise HTTPException(status_code=400, detail="Email, OTP, and new password required")
    
    # Verify OTP
    if not await verify_otp(email, otp, "password_reset"):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # Update password
    hashed_password = hash_password(new_password)
    result = await db["users"].update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "Password reset successfully"}

# Update existing registration endpoints to use OTP verification
@router.post("/register")
async def register_user(user: User):
    existing = await db["users"].find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    user_dict = user.dict()
    user_dict["id"] = str(user_dict["id"])
    user_dict["password"] = hash_password(user_dict["password"])
    user_dict["status"] = "active"
    await db["users"].insert_one(user_dict)
    return {"message": "User registered successfully"}

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
    user_dict["status"] = "pending"
    await db["users"].insert_one(user_dict)
    return {"message": "Employee registered and pending admin approval"}

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

@router.get("/admin/employees/pending")
async def list_pending_employees(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    employees = await db["users"].find({"role": "employee", "org_code": org_code, "status": "pending"}).to_list(length=100)
    for emp in employees:
        emp.pop("password", None)
        if "_id" in emp:
            emp["_id"] = str(emp["_id"])
    return {"pending_employees": employees}

@router.post("/admin/employees/{employee_id}/approve")
async def approve_employee(employee_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    result = await db["users"].update_one({"id": employee_id, "org_code": org_code, "role": "employee", "status": "pending"}, {"$set": {"status": "active"}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Pending employee not found or not in your organization")
    return {"message": "Employee approved and activated"}

@router.post("/admin/employees/{employee_id}/reject")
async def reject_employee(employee_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    result = await db["users"].delete_one({"id": employee_id, "org_code": org_code, "role": "employee", "status": "pending"})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Pending employee not found or not in your organization")
    return {"message": "Employee rejected and deleted"}

# Update normal employee list to only show 'active' employees
@router.get("/admin/employees")
async def get_employees(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    if not org_code:
        raise HTTPException(status_code=400, detail="No organization found for admin")
    employees = await db["users"].find({"role": "employee", "org_code": org_code, "status": "active"}).to_list(length=1000)
    cleaned_employees = []
    for emp in employees:
        emp.pop("password", None)
        if "_id" in emp:
            emp["_id"] = str(emp["_id"])
        cleaned_employees.append(emp)
    return {"employees": cleaned_employees}

@router.get("/admin/employees/{employee_id}")
async def get_employee(employee_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    if not org_code:
        raise HTTPException(status_code=400, detail="No organization found for admin")
    emp = await db["users"].find_one({"id": employee_id, "org_code": org_code, "role": "employee"})
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    emp.pop("password", None)
    if "_id" in emp:
        emp["_id"] = str(emp["_id"])
    return emp

@router.put("/admin/employees/{employee_id}")
async def update_employee(employee_id: str, update: EmployeeUpdateSchema, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    if not org_code:
        raise HTTPException(status_code=400, detail="No organization found for admin")
    update_data = {k: v for k, v in update.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No update fields provided")
    result = await db["users"].update_one({"id": employee_id, "org_code": org_code, "role": "employee"}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found or not in your organization")
    return {"message": "Employee updated successfully"}

@router.delete("/admin/employees/{employee_id}")
async def delete_employee(employee_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    if not org_code:
        raise HTTPException(status_code=400, detail="No organization found for admin")
    result = await db["users"].delete_one({"id": employee_id, "org_code": org_code, "role": "employee"})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found or not in your organization")
    return {"message": "Employee deleted successfully"}

# Keep the token endpoint for backward compatibility
@router.post("/token", response_model=TokenResponse)
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return await login(form_data)

@router.post("/admin/docs/upload")
async def upload_doc(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    if not org_code:
        raise HTTPException(status_code=400, detail="No organization found for admin")
    # Save file (encrypted)
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    content = await file.read()
    encrypted_content = encrypt_bytes(content)
    with open(file_location, "wb") as f:
        f.write(encrypted_content)
    # Store metadata in MongoDB
    doc_meta = {
        "filename": file.filename,
        "content_type": file.content_type,
        "org_code": org_code,
        "uploader": current_user["sub"],
    }
    result = await db["docs"].insert_one(doc_meta)
    return {"message": "File uploaded", "doc_id": str(result.inserted_id)}

@router.get("/documents")
async def list_docs(current_user: dict = Depends(get_current_user)):
    org_code = current_user.get("org")
    docs = await db["docs"].find({"org_code": org_code}).to_list(length=100)
    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return {"docs": docs}

@router.get("/docs/{doc_id}")
async def get_doc(doc_id: str, current_user: dict = Depends(get_current_user)):
    from bson import ObjectId
    doc = await db["docs"].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    # Only allow access to docs in user's org
    org_code = current_user.get("org")
    if doc["org_code"] != org_code:
        raise HTTPException(status_code=403, detail="Not allowed to access this document")
    file_path = os.path.join(UPLOAD_DIR, doc["filename"])
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server")
    # Decrypt file before sending
    with open(file_path, "rb") as f:
        encrypted_content = f.read()
        decrypted_content = decrypt_bytes(encrypted_content)
    # Return as a streaming response
    return StreamingResponse(io.BytesIO(decrypted_content), media_type=doc["content_type"], headers={"Content-Disposition": f"attachment; filename={doc['filename']}"})

class DocUpdateSchema(BaseModel):
    filename: Optional[str] = None
    content_type: Optional[str] = None

@router.put("/admin/docs/{doc_id}")
async def update_doc(doc_id: str, update: DocUpdateSchema, current_user: dict = Depends(get_current_user)):
    from bson import ObjectId
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    doc = await db["docs"].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc["org_code"] != org_code:
        raise HTTPException(status_code=403, detail="Not allowed to update this document")
    update_data = {k: v for k, v in update.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No update fields provided")
    # If filename is changed, rename the file
    UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '../docs_uploads')
    old_path = os.path.join(UPLOAD_DIR, doc["filename"])
    new_path = os.path.join(UPLOAD_DIR, update_data["filename"]) if "filename" in update_data else old_path
    if "filename" in update_data and os.path.exists(old_path):
        os.rename(old_path, new_path)
    result = await db["docs"].update_one({"_id": ObjectId(doc_id)}, {"$set": update_data})
    return {"message": "Document updated"}

@router.delete("/admin/docs/{doc_id}")
async def delete_doc(doc_id: str, current_user: dict = Depends(get_current_user)):
    from bson import ObjectId
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    org_code = current_user.get("org")
    doc = await db["docs"].find_one({"_id": ObjectId(doc_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc["org_code"] != org_code:
        raise HTTPException(status_code=403, detail="Not allowed to delete this document")
    # Delete file from disk
    UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '../docs_uploads')
    file_path = os.path.join(UPLOAD_DIR, doc["filename"])
    if os.path.exists(file_path):
        os.remove(file_path)
    await db["docs"].delete_one({"_id": ObjectId(doc_id)})
    return {"message": "Document deleted"}

