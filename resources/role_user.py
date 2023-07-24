from flask_smorest import Blueprint, abort
from flask.views import MethodView
from flask import jsonify,request
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from db import db
from passlib.hash import pbkdf2_sha256
from models import RoleUserModel,RoleModel,BlockModel
from globalfun import flatten_list_of_dicts
from marshmallow import ValidationError
import json
from sqlalchemy.types import JSON
from flask_jwt_extended import create_access_token,  get_jwt,jwt_required,create_refresh_token,get_jwt_identity,decode_token
from schemas.role_user_schema import RoleUserUpdateStatusSchema, role_user_update_status_schema,role_user_create,RoleLoginSchema,admin_user_change_password_schema,RoleUserViewCreateSchema,role_user_update_schema,admin_user_self_change_password_schema
from sqlalchemy import asc,or_,and_
from datetime import datetime
from blocklist import BLOCKLIST
import uuid
import os

blp = Blueprint("RoleUsers", "RoleUsers", description="Operations on RoleUsers")



@blp.route("/margaret/role-user/create/super-user")
class Role(MethodView):
    def get(self):
        create_at=datetime.now()
        data= RoleUserModel.query.first()
        uid=uuid.uuid4()
        if data is None:
            log={
                "message":"1st User Created",
                "create_at":str(create_at),
                "admin":"11223344"
            }
            role = RoleUserModel(name="Mahabobur Rahman",user_id="1105003",uid=uid,active=True,mobile_number="01521216116",super_admin= True,password= pbkdf2_sha256.hash("12345678"),role_id="11223344",email="mahabub@gmail.com",logs=log,create_at=datetime.utcnow(),
            )
            db.session.add(role)
            db.session.commit()
            return {"message":" 1st User Create succesfully"},201
        
        abort(400,message="Super Admin User is Already Created")

@blp.route("/margaret/role-user/login")
class RoleUserLogin(MethodView):
    @blp.arguments(RoleLoginSchema)
    def post(self, user_data):
        uid=uuid.uuid4()
        user = RoleUserModel.query.filter(
            RoleUserModel.user_id == user_data["user_id"]
        ).first()
        
        if user is None:
             return ({"message":"Invalid user id"} ),401
        access = RoleModel.query.filter(
            RoleModel.uid == user.role_id).first()
        if access is None:
             return ({"message":"Invalid Credintial"} ),401
       
        if   user.active==True and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=user.uid, fresh=True)
            decode_jti=decode_token(access_token)
            if user.token is None:
                RoleUserModel.query.filter(RoleUserModel.user_id==user_data["user_id"]).update({"token":access_token,"jti":decode_jti['jti']})
                db.session.commit()
                token_value = RoleUserModel.query.filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==user_data["user_id"])).first()
                
                return {"access_token": token_value.token,"role_id":user.role_id,"access":access.role,"name":user.name,"user_id":user.user_id}, 201
                
            else:
                decode_value=decode_token(user.token)
                block_token=BlockModel(block_id=uid,token=user.token,user_id=decode_value['sub'],jti=decode_value['jti'],create_at=datetime.utcnow())
                db.session.add(block_token)
                db.session.commit()
                BLOCKLIST.add(decode_value['jti'])
                
                if RoleUserModel.query.filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==user_data["user_id"])).first():
                    RoleUserModel.query.filter(RoleUserModel.user_id==user_data["user_id"]).update({"token":access_token,"jti":decode_jti['jti']})
                    db.session.commit()
                    token_value = RoleUserModel.query.filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==user_data["user_id"])).first()
                    
                    return {"access_token": token_value.token,"role_id":user.role_id,"access":access.role,"name":user.name,"user_id":user.user_id}, 201
                
                # abort(422, message="Another Person Entry your Account.")

            abort(401, message="Invalid Token")

        abort(400, message="Password is not match")


@blp.route('/margaret/role-user/create', methods=['POST'])
@jwt_required()
def get_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")

    if data2.active==True:

        if data2.role['user_management'] =='a':
            if data.active==True:
                if (request.data):
                    json_data=request.get_json()
                    uid=uuid.uuid4()

                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        create_at=datetime.now()
                        request_data = role_user_create.load(json_data)
                        if RoleUserModel.query.filter(or_(RoleUserModel.user_id == request_data["user_id"],RoleUserModel.email == request_data["email"],RoleUserModel.mobile_number == request_data["mobile_number"])).first():abort(409, message="A user with that user id, email or mobile number  already exists.")
                        log={
                            "message":"New User Created",
                            "create_at":str(create_at),
                            "admin":str(current_user)
                        }
                        user = RoleUserModel(name=request_data['name'],uid=uid,user_id=request_data['user_id'],email=request_data['email'],mobile_number=request_data['mobile_number'], password=pbkdf2_sha256.hash(request_data["password"]),active=request_data["active"],create_at=datetime.utcnow(),logs=log,role_id=request_data["role_id"])
                        db.session.add(user)
                        db.session.commit()
                        
                        return {"message":"User Create Succesfully"},201
                    except ValidationError as err:
                        return err.messages, 422
                        
                abort(400,message="This request no data")
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")


@blp.route('/margaret/role-user/<user_id>', methods=['GET'])

class RoleUserOne(MethodView):
    @blp.response(200, RoleUserViewCreateSchema())
    @jwt_required()
    def get(self,user_id):
        x=get_jwt()["jti"]
        current_user = get_jwt_identity()
        data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
        if x!=data.jti:
            abort(401,message="unauthorized User")
        if data is None:
            abort(404,message="User,not found")
        data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
        if data2 is None:
            abort(401,message="Role,not vaild ")
        if data2.active==True:
            if data2.role['user_management'] =='a':
        
                if data.active==True:
                    dbdata= RoleUserModel.query.filter(RoleUserModel.user_id == user_id).first()
                    if dbdata:
                        return dbdata,200
                    abort(404,message="Not found any data")

                abort(401,message="User is not active")

            abort(401,message="This Role is not permitted for you")

        abort(401,message="role is not active")



@blp.route('/margaret/role-user/all', methods=['GET'])
@jwt_required()
def get_user_all():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    if data2.active==True:
        get_data = RoleUserModel.query.all()
        # print(get_data)
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                output=[]
                for i in get_data:
                    
                    output_data = {}
                    output_data['id'] = i.id
                    output_data['uid'] = i.uid
                    output_data['active'] = i.active
                    output_data['name'] = i.name
                    output_data['user_id'] = i.user_id
                    output_data['mobile_number'] = i.mobile_number
                    output_data['email'] = i.email
                    output_data['role_id'] = i.role_id
                    # print(output_data,'..........................')
                    output.append({"data":output_data})
                

                return output,200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")


@blp.route('/margaret/role-user/all-new', methods=['GET'])
class RoleUser(MethodView):
    @blp.response(200, RoleUserViewCreateSchema(many=True))
    @jwt_required()
    def get(self):
        x=get_jwt()["jti"]
        current_user = get_jwt_identity()
        data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
        if x!=data.jti:
            abort(401,message="unauthorized User")
        if data is None:
            abort(404,message="User,not found")
        data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
        if data2 is None:
            abort(401,message="Role,not vaild ")
        if data2.active==True:
            if data2.role['user_management'] =='a':
        
                if data.active==True:
                    dbdata= RoleUserModel.query.all()
                    return dbdata,200
                abort(401,message="User is not active")

            abort(401,message="This Role is not permitted for you")

        abort(400,message="role is not active")


@blp.route('/margaret/role-user/update', methods=['PUT'])
@jwt_required()
def update_user():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    if data2.active==True:

        if data2.role['user_management'] =='a':
        
            if data.active==True:
                
                if (request.data):
                    # print(request.data)
                    json_data=request.get_json()
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        request_data = role_user_update_schema.load(json_data)
                        create_at=datetime.now()
                        update_data= RoleUserModel.query.filter(RoleUserModel.user_id == request_data['user_id']).first() 
                        if not update_data : abort(401,message="This User Id is not Valid")
                        name=update_data.name
                        email=update_data.email
                        mobile_number=update_data.mobile_number
                        role_id=update_data.role_id
                        active=update_data.active
                        # print(json_data)
                        keys=request_data.keys()
                        for i in keys:
                
                            if i =='name':
                                name=request_data["name"]
                            elif i=='email':
                                email=request_data["email"]
                            elif i=='mobile_number':
                                mobile_number=request_data["mobile_number"]
                            elif i=='role':
                                role=request_data["role"]
                            elif i=='active':
                                active=request_data["active"]
                                
                        new_logs={
                            "admin": str(current_user),
                            "message": "user updated",
                            "create_at": str(create_at)
                        }
                        logs = []
                        mak=flatten_list_of_dicts(update_data.logs)
                        logs.append(mak)
                        logs.append(new_logs)
                        one_array_logs=[]
                        for item in logs:
                            if isinstance(item, list):
                                one_array_logs.extend(item)
                            elif isinstance(item, dict):
                                one_array_logs.append(item)
                        RoleUserModel.query.filter(RoleUserModel.user_id==request_data['user_id']).update({"name":name,"email":email,"mobile_number":mobile_number,'role_id':role_id,"active":active,"logs":one_array_logs})
                        db.session.commit()
                        return {"message":"update Sucessfuly"},201
                    except ValidationError as err:
                        return err.messages, 422
                else:
                    return {"message":"This request has not data"},400
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")




@blp.route('/margaret/role-user/update-status', methods=['PUT'])
@jwt_required()
def update_user_status_by_id():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")

    if data2.active==True:

        if data2.role['user_management'] =='a':
        
            if data.active==True:
                
                if (request.data):
                    json_data=request.get_json()
                    # print(json_data)
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        create_at=datetime.now()
                        request_data = role_user_update_status_schema.load(json_data)
                        # print(request_data['user_id'])
                        update_data= RoleUserModel.query.filter(RoleUserModel.user_id == request_data['user_id']).first() 
                        if not update_data : abort(401,message="This User Id is not Valid")
                        
                       
                           
                        if request['active']==True:
                            new_logs={
                                "admin": str(current_user),
                                "message": "user is actived",
                                "create_at": str(create_at)
                            }
                        else:
                            new_logs={
                                "admin": str(current_user),
                                "message": "user is deactived",
                                "create_at": str(create_at)
                            }

                        logs = []
                        mak=flatten_list_of_dicts(update_data.logs)
                        logs.append(mak)
                        logs.append(new_logs)
                        one_array_logs=[]
                        for item in logs:
                            if isinstance(item, list):
                                one_array_logs.extend(item)
                            elif isinstance(item, dict):
                                one_array_logs.append(item)
                        RoleUserModel.query.filter(RoleUserModel.user_id==request_data['user_id']).update({"active":request['active'],"logs":one_array_logs})

                        db.session.commit()
                        return {"message":"status update Sucessfuly"},201
                    except ValidationError as err:
                        return err.messages, 422
                else:
                    return {"message":"This request has not data"},400
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")



# @blp.route('/v1/user-management/user/status-update', methods=['PUT'])
# class RoleUser(MethodView):
#     @blp.arguments(RoleUserUpdateStatusSchema)
#     # @blp.response(200, RoleUserViewCreateSchema())
#     @jwt_required()
#     def put(self,user_data):
#         x=get_jwt()["jti"]
#         current_user = get_jwt_identity()
#         data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
#         if x!=data.jti:
#             abort(401,message="unauthorized User")
#         if data is None:
#             abort(404,message="User,not found")
#         data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
#         if data2 is None:
#             abort(401,message="Role,not vaild ")
#         if data2.active==True:
#             if data2.role['user_management'] =='a':
        
#                 if data.active==True:
#                     update_data=RoleUserModel.query.filter(RoleUserModel.user_id==user_data['user_id']).first()
#                     if not update_data : abort(401,message="This User Id is not Valid")
#                     status=update_data.status
#                     if status!=user_data['status']:
#                         status=user_data['status']
#                         RoleUserModel.query.filter(RoleUserModel.user_id==user_data['user_id']).update({"status":status})

#                         db.session.commit()
#                     return {"message":"update Succesfully"},201
#                 abort(401,message="User is not active")

#             abort(401,message="This Role is not permitted for you")

#         abort(400,message="role is not active")



@blp.route('/margaret/role-user/user/change-password', methods=['PUT'])
@jwt_required()
def update_user_by_id_password():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    if data2.active==True:

        if data2.role['user_management'] =='a':
        
            if data.active==True:
                if (request.data):
                    json_data=request.get_json()
                # print(json_data)
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        create_at=datetime.now()
                        request_data = admin_user_change_password_schema.load(json_data)
                        user_id=request_data["user_id"]
                        # print(user_id)
                        x=RoleUserModel.query.filter(RoleUserModel.user_id==user_id).first()
                        if x is None:
                            # print(x)
                            abort(401,message="User id not Match")
                        new_password=request_data["new_password"]
                       
                        new_logs={
                            "admin": str(current_user),
                            "message": "user password updated",
                            "create_at": str(create_at)
                        }
                        logs = []
                        mak=flatten_list_of_dicts(x.logs)
                        logs.append(mak)
                        logs.append(new_logs)
                        one_array_logs=[]
                        for item in logs:
                            if isinstance(item, list):
                                one_array_logs.extend(item)
                            elif isinstance(item, dict):
                                one_array_logs.append(item)
                        RoleUserModel.query.filter(RoleUserModel.user_id==user_id).update({"password":pbkdf2_sha256.hash(new_password),"logs":one_array_logs})
                        db.session.commit()
                        

                        return {"message":"Password update Sucessfuly"},201
                    except ValidationError as err:
                        return err.messages, 422
                else:
                    return {"message":"This request has not data"},400
            abort(401,message="User is not active")
        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

@blp.route('/margaret/role-user/self/change-password', methods=['PUT'])
@jwt_required()
def update_user_by_self_password():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    if data2.active==True:

        if data2.role['user_management'] =='a':
        
            if data.active==True:
                if (request.data):
                    json_data=request.get_json()
                # print(json_data)
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        request_data = admin_user_self_change_password_schema.load(json_data)
                        user_id=request_data["user_id"]
                        # print(user_id)
                        x=RoleUserModel.query.filter(and_(RoleUserModel.user_id==user_id,RoleUserModel.user_id==data.user_id)).first()
                        if x is None:

                            abort(401,message="My id not Match")
                        
                        new_password=request_data["new_password"]
                        old_password=request_data["old_password"]
                        if data and pbkdf2_sha256.verify(old_password, data.password):
                            create_at=datetime.now()
                            new_logs={
                                "admin": str(current_user),
                                "message": "user password updated",
                                "create_at": str(create_at)
                            }
                            logs = []
                            mak=flatten_list_of_dicts(x.logs)
                            logs.append(mak)
                            logs.append(new_logs)
                            one_array_logs=[]
                            for item in logs:
                                if isinstance(item, list):
                                    one_array_logs.extend(item)
                                elif isinstance(item, dict):
                                    one_array_logs.append(item)
                            RoleUserModel.query.filter(RoleUserModel.user_id==user_id).update({"password":pbkdf2_sha256.hash(new_password),"logs":one_array_logs})
                            db.session.commit()
                        else:
                            return {"message": "Old password doesn't match "}, 400

                        return {"message":"Password update Sucessfuly"},201
                    except ValidationError as err:
                        return err.messages, 422
                else:
                    return {"message":"This request has not data"},400
            abort(401,message="User is not active")
        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")



@blp.route("/v1/user-management/user/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        
        x=BLOCKLIST.add(jti)
        
        return {"message": "Successfully logged out ,,,,"}, 201


@blp.route('/margaret/role-user/delete/<int:user_id>', methods=['DELETE'])
@jwt_required()
def create_role(user_id):
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")

    if data.user_id==user_id and data2.super_admin==True:
       
        abort(400,message="permition denied")
    if data2.active==True:
        

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                
                role_data=RoleUserModel.query.filter(RoleUserModel.user_id==user_id).first()
                if role_data is None:
                    abort(400,message="User is not found")

                RoleUserModel.query.filter(RoleUserModel.user_id==user_id).delete()
                db.session.commit()

                
                return jsonify({'message' : 'Deleted Succesfully!'}),201
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")



