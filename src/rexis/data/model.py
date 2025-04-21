from pgvector.sqlalchemy import Vector
from sqlalchemy import ARRAY, Column, DateTime, Integer, Text, func
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Document(Base):
    __tablename__ = 'documents'

    id = Column(Integer, primary_key=True)
    content = Column(Text, nullable=False)
    embedding = Column(Vector(1536), nullable=False)
    tags = Column(ARRAY(Text), default=[])  # Optional tags list
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Full-text search column (indexed separately)
    content_tsv = Column(TSVECTOR)
