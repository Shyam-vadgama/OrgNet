from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET = "your-secret-key"

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed):
    return pwd_context.verify(plain_password, hashed)

def create_token(user):
    payload = {
        "sub": user.id,
        "role": user.role,
        "org": user.org,  # Use 'org' instead of 'org_id'
        "exp": datetime.utcnow() + timedelta(hours=6)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def get_current_user(token: str = Depends(oauth2_scheme)):
    print(f"[DEBUG] Token received for verification: {token}")
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        print(f"[DEBUG] Token decoded successfully: {payload}")
        return payload
    except JWTError as e:
        print(f"[DEBUG] Token decode error: {e}")
        raise HTTPException(401, "Invalid token")