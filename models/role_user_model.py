from db import db
from sqlalchemy.types import JSON
import datetime


class RoleUserModel(db.Model):
    __tablename__ = "roleusers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80),nullable=False)
    user_id = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(11), unique=True, nullable=False)
    uid = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    token = db.Column(db.String(500),unique=True,nullable=True)
    jti = db.Column(db.String(80),unique=True,nullable=True)
    role_id = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean,nullable=True)
    super_admin = db.Column(db.Boolean,nullable=True)
    info1 = db.Column(db.String(255), nullable=True)
    info2 = db.Column(db.String(255), nullable=True)
    extra_info = db.Column(JSON)
    logs = db.Column(JSON)
    create_at=db.Column(db.DateTime, nullable=True)
   
    