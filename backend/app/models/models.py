from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid
import enum

class ScanStatus(str, enum.Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"

class RiskLevel(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"

class User(Base):
    __tablename__ = "users"
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email      = Column(String, unique=True, nullable=False)
    name       = Column(String, nullable=False)
    password   = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    scans      = relationship("Scan", back_populates="user", cascade="all, delete")

class Scan(Base):
    __tablename__ = "scans"
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, ForeignKey("users.id"), nullable=True)
    domain     = Column(String, nullable=False)
    status     = Column(String, default=ScanStatus.pending)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    assets     = relationship("Asset", back_populates="scan", cascade="all, delete")
    user       = relationship("User", back_populates="scans")

class Asset(Base):
    __tablename__ = "assets"
    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id      = Column(String, ForeignKey("scans.id"), nullable=False)
    subdomain    = Column(String, nullable=False)
    ip_address   = Column(String, nullable=True)
    open_ports   = Column(Text, nullable=True)
    technologies = Column(Text, nullable=True)
    status_code  = Column(Integer, nullable=True)
    country      = Column(String, nullable=True)
    asn          = Column(String, nullable=True)
    created_at   = Column(DateTime, server_default=func.now())
    scan         = relationship("Scan", back_populates="assets")
    findings     = relationship("Finding", back_populates="asset", cascade="all, delete")
    threat_intel = relationship("ThreatIntel", back_populates="asset", cascade="all, delete")

class Finding(Base):
    __tablename__ = "findings"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id    = Column(String, ForeignKey("assets.id"), nullable=False)
    title       = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    risk        = Column(String, default=RiskLevel.info)
    risk_score  = Column(Float, default=0.0)
    source      = Column(String, nullable=True)
    evidence    = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())
    asset       = relationship("Asset", back_populates="findings")

class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id     = Column(String, ForeignKey("assets.id"), nullable=False)
    source       = Column(String, nullable=False)
    is_malicious = Column(Integer, default=0)
    raw_data     = Column(Text, nullable=True)
    checked_at   = Column(DateTime, server_default=func.now())
    asset        = relationship("Asset", back_populates="threat_intel")