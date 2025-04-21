from pgvector.sqlalchemy import Vector
from sqlalchemy import ARRAY, Column, DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), nullable=False, unique=True)
    content = Column(Text, nullable=False)
    embedding = Column(Vector(1536), nullable=False)
    tags = Column(ARRAY(Text), default=[])
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    content_tsv = Column(TSVECTOR)

    __table_args__ = (UniqueConstraint("sha256", name="uq_documents_sha256"),)
