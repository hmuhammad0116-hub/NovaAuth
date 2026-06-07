from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from database import Base

class App(Base):
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    secret = Column(String(255), nullable=False)
    version = Column(String(50), default="1.0.0")
    status = Column(String(30), default="active")
    created_at = Column(DateTime, server_default=func.now())

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String(100), index=True, nullable=False)
    username = Column(String(100), index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    hwid = Column(String(255), nullable=True)
    banned = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String(100), index=True, nullable=False)
    license_key = Column(String(255), unique=True, index=True, nullable=False)
    used = Column(Boolean, default=False)
    used_by = Column(Integer, nullable=True)
    duration_days = Column(Integer, default=30)
    created_at = Column(DateTime, server_default=func.now())

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    token = Column(Text, nullable=False)
    ip = Column(String(100), nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String(100), nullable=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(255), nullable=False)
    ip = Column(String(100), nullable=True)
    created_at = Column(DateTime, server_default=func.now())