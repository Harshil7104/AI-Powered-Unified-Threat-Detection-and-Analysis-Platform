import hashlib
import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database.db import get_db
from database.models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Passwords hashing using built-in hashlib pbkdf2
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    db_val = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + db_val.hex()

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt_hex, hash_hex = hashed.split(":")
        salt = bytes.fromhex(salt_hex)
        db_val = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return db_val.hex() == hash_hex
    except Exception:
        return False

# Pydantic Schemas
class AuthRequest(BaseModel):
    email: str
    password: str

class AuthResponse(BaseModel):
    message: str
    email: str
    isLoggedIn: bool

@router.post("/register", response_model=AuthResponse)
def register(payload: AuthRequest, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists."
        )
    
    if len(payload.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters long."
        )
        
    # Create new user
    new_user = User(
        email=payload.email,
        password_hash=hash_password(payload.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "message": "User registered successfully.",
        "email": new_user.email,
        "isLoggedIn": True
    }

@router.post("/login", response_model=AuthResponse)
def login(payload: AuthRequest, db: Session = Depends(get_db)):
    # Fetch user
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
        
    return {
        "message": "Login successful.",
        "email": user.email,
        "isLoggedIn": True
    }
