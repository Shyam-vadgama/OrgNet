from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from cryptography.fernet import Fernet
import base64
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET = "your-secret-key"
FERNET_KEY = b'Qk1Qb3JwQ2h6b3J6b2J6b3JwQ2h6b3J6b3JwQ2h6b3I='
fernet = Fernet(FERNET_KEY)

# SMTP Configuration (you'll need to set these in environment variables)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "your-email@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your-app-password")

# OTP Configuration
OTP_EXPIRY_MINUTES = 10

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed):
    return pwd_context.verify(plain_password, hashed)

def create_token(user):
    payload = {
        "sub": user.id,
        "role": user.role,
        "org": user.org,
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

def encrypt_bytes(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_bytes(token: bytes) -> bytes:
    return fernet.decrypt(token)

def generate_otp(length: int = 6) -> str:
    """Generate a random OTP of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def send_email_otp(to_email: str, otp: str, subject: str = "OTP Verification"):
    """Send OTP via email using SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = to_email
        msg['Subject'] = subject
        
        body = f"""
        Your OTP for verification is: {otp}
        
        This OTP will expire in {OTP_EXPIRY_MINUTES} minutes.
        
        If you didn't request this OTP, please ignore this email.
        
        Best regards,
        Your Application Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, to_email, text)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

def create_otp_record(email: str, purpose: str = "verification") -> dict:
    """Create an OTP record with expiration"""
    otp = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    return {
        "email": email,
        "otp": otp,
        "purpose": purpose,
        "expires_at": expiry,
        "created_at": datetime.utcnow(),
        "used": False
    }

async def verify_otp(email: str, otp: str, purpose: str = "verification") -> bool:
    from db.config import db

    # Find the OTP record
    otp_record = await db["otps"].find_one({
        "email": email,
        "otp": otp,
        "purpose": purpose,
        "used": False,
        "expires_at": {"$gt": datetime.utcnow()}
    })

    if otp_record:
        # Mark OTP as used
        await db["otps"].update_one(
            {"_id": otp_record["_id"]},
            {"$set": {"used": True}}
        )
        return True

    return False