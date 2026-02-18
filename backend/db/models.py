"""
SQLAlchemy ORM 모델
기존 MySQL 스키마와 정확히 일치하도록 작성
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, VARCHAR
)
from sqlalchemy.orm import relationship
from .base import Base


class Server(Base):
    """서버 테이블"""
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(VARCHAR(100), unique=True, nullable=False)
    company = Column(VARCHAR(100), nullable=False)
    hostname = Column(VARCHAR(100), nullable=False)
    ip_address = Column(VARCHAR(45), nullable=False)
    ssh_port = Column(VARCHAR(10), nullable=False, default="22")
    os_type = Column(VARCHAR(100), nullable=False)
    db_type = Column(VARCHAR(100), nullable=True)
    db_port = Column(VARCHAR(10), nullable=True)
    db_user = Column(VARCHAR(100), nullable=True)
    db_passwd = Column(Text, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    manager = Column(VARCHAR(100), nullable=False)
    department = Column(VARCHAR(100), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="server")
    remediation_logs = relationship("RemediationLog", back_populates="server")
    exceptions = relationship("Exception", back_populates="server")


class KisaItem(Base):
    """KISA 점검 항목 테이블"""
    __tablename__ = "kisa_items"

    item_code = Column(VARCHAR(10), primary_key=True)
    category = Column(VARCHAR(50), nullable=False)
    title = Column(VARCHAR(200), nullable=False)
    severity = Column(VARCHAR(10), nullable=False)
    description = Column(VARCHAR(500), nullable=False)
    auto_fix = Column(Boolean, nullable=False, default=True)
    auto_fix_description = Column(VARCHAR(500), nullable=True)
    guide = Column(VARCHAR(1000), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="kisa_item")
    remediation_logs = relationship("RemediationLog", back_populates="kisa_item")
    exceptions = relationship("Exception", back_populates="kisa_item")


class ScanHistory(Base):
    """점검 이력 테이블"""
    __tablename__ = "scan_history"

    scan_id = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(VARCHAR(100), ForeignKey("servers.server_id"), nullable=False)
    item_code = Column(VARCHAR(10), ForeignKey("kisa_items.item_code"), nullable=False)
    status = Column(VARCHAR(10), nullable=False)
    raw_evidence = Column(Text, nullable=False)
    scan_date = Column(DateTime, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="scan_history")
    kisa_item = relationship("KisaItem", back_populates="scan_history")


class RemediationLog(Base):
    """조치 이력 테이블"""
    __tablename__ = "remediation_logs"

    log_id = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(VARCHAR(100), ForeignKey("servers.server_id"), nullable=False)
    item_code = Column(VARCHAR(10), ForeignKey("kisa_items.item_code"), nullable=False)
    action_date = Column(DateTime, nullable=False)
    is_success = Column(Boolean, nullable=False)
    failure_reason = Column(VARCHAR(500), nullable=True)
    raw_evidence = Column(Text, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="remediation_logs")
    kisa_item = relationship("KisaItem", back_populates="remediation_logs")


class Exception(Base):
    """예외 관리 테이블"""
    __tablename__ = "exceptions"

    exception_id = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(VARCHAR(100), ForeignKey("servers.server_id"), nullable=False)
    item_code = Column(VARCHAR(10), ForeignKey("kisa_items.item_code"), nullable=False)
    reason = Column(VARCHAR(500), nullable=False)
    valid_date = Column(DateTime, nullable=False)

    # Relationships
    server = relationship("Server", back_populates="exceptions")
    kisa_item = relationship("KisaItem", back_populates="exceptions")


class User(Base):
    """사용자 테이블"""
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    user_name = Column(VARCHAR(100), unique=True, nullable=False)
    user_passwd = Column(VARCHAR(255), nullable=False)
    prev_user_passwd = Column(VARCHAR(255), nullable=True)
    role = Column(VARCHAR(20), nullable=False, default="VIEWER")
    company = Column(VARCHAR(100), nullable=False)
    must_change_password = Column(Boolean, nullable=False, default=True)
    password_changed_at = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)
