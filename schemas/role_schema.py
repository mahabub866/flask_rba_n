
from marshmallow import Schema, fields
from marshmallow_jsonschema import JSONSchema
import enum
#role  schemas
class RoleViewSchema(Schema):
    id=fields.Integer()
    active=fields.Boolean()
    name = fields.Str()
    role=JSONSchema()

class RoleSchemaCreate(Schema):
    name = fields.Str(required=True)
    active = fields.Boolean(required=False, missing=True)
    user_management = fields.Str(required=False, missing='a')
    tv_app_management = fields.Str(required=False, missing='a')
    app_management = fields.Str(required=False, missing='a')
    end_tv_app_user_management = fields.Str(required=False, missing='a')

    
class RoleSchemaUpdate(Schema):
    uid = fields.Str(required=True)
    name = fields.Str(required=True)
    active = fields.Boolean(required=False, missing=True)
    user_management = fields.Str(required=False, missing='a')
    tv_app_management = fields.Str(required=False, missing='a')
    app_management = fields.Str(required=False, missing='a')
    end_tv_app_user_management = fields.Str(required=False, missing='a')


class RoleSchemaUpdateStatus(Schema):
    uid = fields.Str(required=True)
    active = fields.Boolean(required=True)


role_create_schema=RoleSchemaCreate()
role_update_schema=RoleSchemaUpdate()
role_update_status_schema=RoleSchemaUpdateStatus()
role_update_name_schema=RoleSchemaUpdateStatus()