"""
Team Availability App - backend (single file)

COMPLETE BACKEND: database tables, login (JWT), availability (with
"available till"), admin dashboard + filters, user management.
"""
import os
from contextlib import asynccontextmanager
from datetime import date as date_cls
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import (
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ---------------------------------------------------------------
# CONFIG (set these as environment variables on Render)
# ---------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")  # local default
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-in-production")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
TOKEN_HOURS = 24 * 7  # login stays valid for 7 days

# ---------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(10), nullable=False, default="user")  # admin | user
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Availability(Base):
    # Created now so we don't need migrations later. Used from step 2.
    __tablename__ = "availability"
    __table_args__ = (UniqueConstraint("user_id", "date", name="uq_user_date"),)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    date = Column(Date, nullable=False)
    status = Column(String(20), nullable=False)  # available | unavailable | working_on_video
    available_until = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------
# AUTH HELPERS
# ---------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def create_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "exp": utcnow() + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


bearer = HTTPBearer()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    try:
        data = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        user = db.get(User, int(data["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# ---------------------------------------------------------------
# APP SETUP
# ---------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    # Create the first admin automatically if none exists
    with SessionLocal() as db:
        if not db.query(User).filter(User.role == "admin").first():
            db.add(
                User(
                    name="Admin",
                    username=ADMIN_USERNAME.strip().lower(),
                    password_hash=hash_password(ADMIN_PASSWORD),
                    role="admin",
                )
            )
            db.commit()
    yield


app = FastAPI(title="Team Availability API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------
# SCHEMAS
# ---------------------------------------------------------------
class LoginIn(BaseModel):
    username: str
    password: str


class CreateUserIn(BaseModel):
    name: str
    username: str
    password: str
    role: str = "user"  # admin | user


class ResetPasswordIn(BaseModel):
    new_password: str


def user_out(u: User) -> dict:
    return {"id": u.id, "name": u.name, "username": u.username, "role": u.role}


# ---------------------------------------------------------------
# STEP 1 ENDPOINTS
# ---------------------------------------------------------------
@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username.strip().lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {"token": create_token(user), "user": user_out(user)}


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_out(user)


@app.post("/admin/users", status_code=201)
def admin_create_user(
    body: CreateUserIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    username = body.username.strip().lower()
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already taken")
    user = User(
        name=body.name.strip(),
        username=username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user_out(user)


@app.get("/admin/users")
def admin_list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return [user_out(u) for u in db.query(User).order_by(User.name).all()]


@app.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    body: ResetPasswordIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"reset": user_id}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.query(Availability).filter(Availability.user_id == user_id).delete()
    db.delete(user)
    db.commit()
    return {"deleted": user_id}


# ---------------------------------------------------------------
# AVAILABILITY HELPERS (all times stored in UTC, shown in IST)
# ---------------------------------------------------------------
IST = timezone(timedelta(hours=5, minutes=30))
STATUSES = ("available", "unavailable", "working_on_video")


def today_ist() -> date_cls:
    return datetime.now(IST).date()


def as_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:  # SQLite returns naive datetimes
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_ist(dt):
    dt = as_utc(dt)
    return dt.astimezone(IST) if dt else None


def time_label(dt):
    d = to_ist(dt)
    return d.strftime("%I:%M %p").lstrip("0") if d else None


def display_status(row) -> str:
    """available | available_ended | unavailable | working_on_video | not_responded"""
    if row is None:
        return "not_responded"
    if (
        row.status == "available"
        and row.available_until is not None
        and as_utc(row.available_until) <= utcnow()
    ):
        return "available_ended"
    return row.status


def availability_out(row) -> dict:
    if row is None:
        return {
            "status": None,
            "display_status": "not_responded",
            "available_until": None,
            "available_until_label": None,
            "updated_at": None,
            "updated_at_label": None,
        }
    return {
        "status": row.status,
        "display_status": display_status(row),
        "available_until": to_ist(row.available_until).isoformat() if row.available_until else None,
        "available_until_label": time_label(row.available_until),
        "updated_at": to_ist(row.updated_at).isoformat() if row.updated_at else None,
        "updated_at_label": time_label(row.updated_at),
    }


def get_row(db: Session, user_id: int, day: date_cls):
    return (
        db.query(Availability)
        .filter(Availability.user_id == user_id, Availability.date == day)
        .first()
    )


# ---------------------------------------------------------------
# USER: SET / VIEW / EXTEND OWN AVAILABILITY
# ---------------------------------------------------------------
class SetAvailabilityIn(BaseModel):
    date: Optional[date_cls] = None  # default: today (IST)
    status: str  # available | unavailable | working_on_video
    available_until: Optional[datetime] = None  # ISO time, e.g. 2026-10-19T14:00:00+05:30
    available_for_minutes: Optional[int] = None  # chips: 60 / 120 / 180 (today only)


class ExtendIn(BaseModel):
    minutes: int = 60


@app.get("/me/availability")
def get_my_availability(
    date: Optional[date_cls] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    day = date or today_ist()
    return {"date": day.isoformat(), **availability_out(get_row(db, user.id, day))}


@app.put("/me/availability")
def set_my_availability(
    body: SetAvailabilityIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    day = body.date or today_ist()
    if day < today_ist():
        raise HTTPException(status_code=400, detail="Cannot set availability for a past date")
    if body.status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {STATUSES}")

    until = None
    has_time = body.available_until is not None or body.available_for_minutes is not None
    if body.status != "available" and has_time:
        raise HTTPException(status_code=400, detail="'Available till' is only allowed with status 'available'")

    if body.status == "available":
        if body.available_until is not None:
            until = body.available_until
            if until.tzinfo is None:
                until = until.replace(tzinfo=IST)
            until = until.astimezone(timezone.utc)
        elif body.available_for_minutes is not None:
            if day != today_ist():
                raise HTTPException(status_code=400, detail="available_for_minutes works for today only")
            if not 1 <= body.available_for_minutes <= 1440:
                raise HTTPException(status_code=400, detail="available_for_minutes must be 1-1440")
            until = utcnow() + timedelta(minutes=body.available_for_minutes)
        if until is not None and until <= utcnow():
            raise HTTPException(status_code=400, detail="'Available till' must be a future time")

    row = get_row(db, user.id, day)
    if row is None:
        row = Availability(user_id=user.id, date=day)
        db.add(row)
    row.status = body.status
    row.available_until = until
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return {"date": day.isoformat(), **availability_out(row)}


@app.post("/me/availability/extend")
def extend_my_availability(
    body: ExtendIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not 1 <= body.minutes <= 720:
        raise HTTPException(status_code=400, detail="minutes must be 1-720")
    day = today_ist()
    row = get_row(db, user.id, day)
    if not row or row.status != "available" or row.available_until is None:
        raise HTTPException(status_code=400, detail="No 'available till' time to extend for today")
    base = max(as_utc(row.available_until), utcnow())
    row.available_until = base + timedelta(minutes=body.minutes)
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return {"date": day.isoformat(), **availability_out(row)}


# ---------------------------------------------------------------
# ADMIN: DASHBOARD (everyone's availability) + FILTERS
# ---------------------------------------------------------------
@app.get("/admin/availability")
def admin_availability(
    date: Optional[date_cls] = None,
    filter: str = "all",  # all | available_now | not_responded
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    if filter not in ("all", "available_now", "not_responded"):
        raise HTTPException(status_code=400, detail="filter must be all, available_now or not_responded")
    day = date or today_ist()

    users = db.query(User).filter(User.role == "user").order_by(User.name).all()
    rows = db.query(Availability).filter(Availability.date == day).all()
    by_user = {r.user_id: r for r in rows}

    items = []
    counts = {
        "available": 0,
        "available_ended": 0,
        "unavailable": 0,
        "working_on_video": 0,
        "not_responded": 0,
    }
    for u in users:
        info = availability_out(by_user.get(u.id))
        counts[info["display_status"]] += 1
        items.append({"user_id": u.id, "name": u.name, "username": u.username, **info})

    if filter == "available_now":
        items = [i for i in items if i["display_status"] == "available"]
    elif filter == "not_responded":
        items = [i for i in items if i["display_status"] == "not_responded"]

    return {"date": day.isoformat(), "filter": filter, "counts": counts, "users": items}
