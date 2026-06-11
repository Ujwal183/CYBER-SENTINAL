"""
🛡️ Cyber Sentinel - Auth API Routes
Handles registration, login, user management.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.core.security import hash_password, verify_password, create_access_token, get_current_user, require_role
from backend.models.user import User
from backend.schemas.schemas import UserRegister, UserLogin, TokenResponse, UserResponse, UserUpdate
from backend.services.threat_service import log_audit

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse)
def register(data: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already exists")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already exists")
    user = User(username=data.username, email=data.email, hashed_password=hash_password(data.password), full_name=data.full_name, role="viewer")
    db.add(user); db.commit(); db.refresh(user)
    token = create_access_token({"sub": str(user.id), "role": user.role})
    log_audit(db, user.id, user.username, "register", "users")
    return TokenResponse(access_token=token, user=UserResponse(**user.to_dict()))

@router.post("/login", response_model=TokenResponse)
def login(data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    token = create_access_token({"sub": str(user.id), "role": user.role})
    log_audit(db, user.id, user.username, "login", "users")
    return TokenResponse(access_token=token, user=UserResponse(**user.to_dict()))

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.to_dict())

@router.get("/users", response_model=list[UserResponse])
def list_users(current_user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    return [UserResponse(**u.to_dict()) for u in db.query(User).all()]

@router.put("/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, current_user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(404, "User not found")
    if data.full_name is not None: user.full_name = data.full_name
    if data.email is not None: user.email = data.email
    if data.role is not None: user.role = data.role
    if data.is_active is not None: user.is_active = data.is_active
    db.commit(); db.refresh(user)
    return user.to_dict()
