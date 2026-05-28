from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Index
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True)
    target_ip = Column(String, nullable=False)
    target_name = Column(String)
    profile = Column(String, nullable=False)
    status = Column(String, nullable=False, default="created")
    current_phase = Column(String)
    created_at = Column(String, nullable=False)
    started_at = Column(String)
    completed_at = Column(String)
    error_msg = Column(Text)
    options = Column(Text)  # JSON blob

    phases = relationship("Phase", back_populates="job", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="job", cascade="all, delete-orphan")
    flags = relationship("Flag", back_populates="job", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="job", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_jobs_status", "status"),)


class Phase(Base):
    __tablename__ = "phases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    phase = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")
    started_at = Column(String)
    completed_at = Column(String)
    error_msg = Column(Text)

    job = relationship("Job", back_populates="phases")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    phase = Column(String, nullable=False)
    tool = Column(String, nullable=False)
    finding_type = Column(String, nullable=False)
    severity = Column(String)
    value = Column(Text, nullable=False)
    metadata_ = Column("metadata", Text)  # JSON blob
    timestamp = Column(String, nullable=False)

    job = relationship("Job", back_populates="findings")

    __table_args__ = (Index("ix_findings_job_id", "job_id"),)


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    service = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    port = Column(Integer)
    valid = Column(Integer, nullable=False, default=1)
    found_by = Column(String)
    timestamp = Column(String, nullable=False)

    job = relationship("Job", back_populates="credentials")

    __table_args__ = (Index("ix_credentials_job_id", "job_id"),)


class Flag(Base):
    __tablename__ = "flags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    flag_type = Column(String, nullable=False)  # user | root | unknown
    value = Column(String, nullable=False)
    path = Column(String)
    submitted = Column(Integer, default=0)
    timestamp = Column(String, nullable=False)

    job = relationship("Job", back_populates="flags")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    phase = Column(String)
    tool = Column(String)
    level = Column(String, nullable=False, default="info")
    message = Column(Text, nullable=False)
    timestamp = Column(String, nullable=False)

    job = relationship("Job", back_populates="logs")

    __table_args__ = (Index("ix_logs_job_id_timestamp", "job_id", "timestamp"),)
