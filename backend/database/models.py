import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from database.db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)  # 'url', 'email', 'file'
    target = Column(String(255), nullable=False)     # e.g., URL string, sender/subject, file name
    risk_score = Column(Integer, nullable=False)
    status = Column(String(50), nullable=False)       # 'Safe', 'Suspicious', 'High Risk'
    details = Column(JSON, nullable=True)            # Detailed JSON response from scan
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
