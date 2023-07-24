# from sqlalchemy.dialects.postgresql import JSON
from db import db
import datetime
from sqlalchemy.types import JSON
class RoleModel(db.Model):
    __tablename__ = "roles"
    
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(80), unique=True, nullable=False)
    super_admin=db.Column(db.Boolean,default=True)
    active=db.Column(db.Boolean,default=True)
    role = db.Column(JSON)
    info1 = db.Column(db.String(255), nullable=True)
    info2 = db.Column(db.String(255), nullable=True)
    extra_info = db.Column(JSON)
    logs = db.Column(JSON)
    create_at=db.Column(db.DateTime, nullable=True)
