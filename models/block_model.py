from sqlalchemy.types import JSON
from db import db

class BlockModel(db.Model):
    __tablename__ = "blocks"
    
    id = db.Column(db.Integer, primary_key=True)
    block_id = db.Column(db.String(255), unique=True, nullable=False)
    token = db.Column(db.String(355), unique=True, nullable=False)
    user_id=db.Column(db.String(255),  nullable=False)
    jti=db.Column(db.String(255),  unique=True, nullable=False)
    info1 = db.Column(db.String(255), nullable=True)
    info2 = db.Column(db.String(255), nullable=True)
    extra_info = db.Column(JSON)
    logs = db.Column(JSON)
    create_at=db.Column(db.DateTime, nullable=True)