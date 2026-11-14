"""
Guardian-Sentinel: Database Persistence Module
Lightweight, thread-safe SQLite persistence using SQLAlchemy ORM.
"""

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DB_PATH

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DBTrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(50), index=True)
    destination_ip = Column(String(50))
    attack_type = Column(String(50), index=True)
    confidence = Column(Float)
    severity = Column(String(20), index=True)
    decision = Column(String(30))
    reputation_score = Column(Integer)
    repeat_offender = Column(Boolean, default=False)
    is_zero_day = Column(Boolean, default=False)
    reconstruction_error = Column(Float, nullable=True)
    explanation = Column(Text)
    recommendation = Column(Text)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auto-initialize tables
init_db()
