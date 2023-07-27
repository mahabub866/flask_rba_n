from models import RoleUserModel,RoleModel,BlockModel
from flask_smorest import abort

def flatten_list_of_dicts(logs):
    result = []
    for item in logs:
        if isinstance(item, list):
            result.extend(item)
        elif isinstance(item, dict):
            result.append(item)
    return result

def validation_user_management(x,current_user):
    data= RoleUserModel.query.filter(RoleUserModel.user_id== current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(404,message="Role,not vaild ")
    if data2.active==True:
       
        
        if data2.role['user_management'] =='a':
    
            if data.active==True:
                return True
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")