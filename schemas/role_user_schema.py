from marshmallow import Schema, fields
from marshmallow_jsonschema import JSONSchema
import enum

#role user schemas

class RoleUserCreateSchema(Schema):
    name=fields.Str(required=True)
    user_id=fields.Str(required=True)
    mobile_number = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)
    active = fields.Boolean(required=True)
    role_id= fields.Str(required=True)

class RoleUserViewCreateSchema(Schema):
    id=fields.Int()
    uid=fields.Str()
    name=fields.Str()
    user_id=fields.Str()
    mobile_number = fields.Str()
    email = fields.Email()
    active = fields.Boolean()
    role= fields.Str()
    
class RoleUserUpdateSchema(Schema):
    uid=fields.Str(required=True)
    name=fields.Str(required=True)
    active=fields.Boolean(required=True)
    mobile_number = fields.Str(required=True)
    role = fields.Str(required=True)
    email = fields.Email(required=True)

class RoleUserUpdateStatusSchema(Schema):
    uid=fields.Str(required=True)
    active = fields.Boolean(required=True)

class AdminSelfUserChangePasswordSchema(Schema):
    user_id=fields.Str(required=True)
    new_password=fields.Str(required=True)
    old_password=fields.Str(required=True)
    
class AdminUserChangePasswordSchema(Schema):
    user_id=fields.Str(required=True)
    new_password=fields.Str(required=True)
    
class RoleLoginSchema(Schema):
    user_id = fields.Str(required=True)
    password = fields.Str(required=True)

role_user_update_schema = RoleUserUpdateSchema()
role_user_update_status_schema = RoleUserUpdateStatusSchema()
admin_user_change_password_schema = AdminUserChangePasswordSchema()
admin_user_self_change_password_schema = AdminSelfUserChangePasswordSchema()
role_user_create=RoleUserCreateSchema()
