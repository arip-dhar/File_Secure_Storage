from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary, DateTime
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False) 
    upload_salt = Column(String, nullable=False)
    
    owned_files = relationship("File", back_populates="owner")
    shared_key_mappings = relationship("SharedFileKey", back_populates="user")

class File(Base):
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    secure_name = Column(String, unique=True, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    file_hash = Column(String, index=True, nullable=True) 
    hmac_tag = Column(String, nullable=True) 
    
    encrypted_owner_key = Column(LargeBinary, nullable=False)
    
    owner = relationship("User", back_populates="owned_files")
    shared_keys = relationship("SharedFileKey", back_populates="file", cascade="all, delete-orphan")

class SharedFileKey(Base):
    __tablename__ = "shared_file_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    file_id = Column(Integer, ForeignKey("files.id"))
    encrypted_recipient_key = Column(LargeBinary, nullable=False)
    expires_at = Column(DateTime, nullable=False) 
    
    user = relationship("User", back_populates="shared_key_mappings")
    file = relationship("File", back_populates="shared_keys")

# NEW COMPONENT: Encrypted Audit Log Table Configuration
class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    action = Column(String, index=True, nullable=False) # e.g., "LOGIN", "UPLOAD"
    
    # Store the log details cryptographically masked
    encrypted_message = Column(LargeBinary, nullable=False)