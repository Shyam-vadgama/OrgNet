from fastapi import Depends, HTTPException
from utils import get_current_user

def is_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admins only")
    return user

def is_authorized(user=Depends(get_current_user)):
    return user  # student or employee allowed