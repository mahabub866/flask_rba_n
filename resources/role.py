from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask import jsonify,request
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from db import db
from models import RoleModel
import json
from globalfun import flatten_list_of_dicts
import uuid
from datetime import datetime
from marshmallow import ValidationError
from sqlalchemy.types import JSON
from flask_jwt_extended import create_access_token,  get_jwt,jwt_required,create_refresh_token,get_jwt_identity
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.dialects import postgresql
from sqlalchemy import select, func,asc
from schemas.role_schema import role_update_schema,role_create_schema,role_update_schema,role_update_status_schema,role_update_name_schema
from models import RoleUserModel
from sqlalchemy import asc,or_,and_
blp = Blueprint("Roles", "Roles", description="Operations on Roles")

@blp.route("/role/super-admin")
class Role(MethodView):
    def get(self):
        data= RoleModel.query.filter(RoleModel.super_admin==True).first()
        if  data is None :
            create_at=datetime.now()
            log={
                "message":"1st User Created",
                "create_at":str(create_at),
                "admin":"11223344"
            }
            role = RoleModel(name="Super Admin",uid='11223344',active=True,super_admin=True,create_at=datetime.utcnow(),
            role={"user_management" : 'a',"tv_app_management":'a',"app_management":'a',"end_tv_app_user_management":'a'},logs=log)
            db.session.add(role)
            db.session.commit()
        else:
            abort(400,message="Super Admin Already Created")
        return " 1st Role Create succesfully",201

@blp.route('/margaret/role/create', methods=['POST'])
@jwt_required()
def create_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
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
                if (request.data):
                    json_data=request.get_json()
                    uid=uid.uid4()
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        request_data = role_create_schema.load(json_data)
                      
                        get_data = RoleModel.query.filter_by(name=request_data['name']).first()
                    
                        if get_data:
                            return {"message": "Name Already Exist"}, 422
                
                        user_management='i'
                        tv_app_management='i'
                        app_management='i'
                        end_tv_app_user_management='i'
                       
                       
                        
                            
                        # print(keys)
                        create_at=datetime.now()
                        log={
                            "message":"New User Created",
                            "create_at":str(create_at),
                            "admin":str(current_user)
                        }
                        role = RoleModel(uid=uid,name=request_data['name'],super_admin=False,active=request_data['active'],create_at=datetime.utcnow(),role={"user_management" : user_management,
                        "tv_app_management":tv_app_management,"end_tv_app_user_management":end_tv_app_user_management,"app_management":app_management},logs=log)
                        # role = request_data

                        # print(role)

                        db.session.add(role)
                        db.session.commit()
               
                        return "Create Succesfully",201
                    except ValidationError as err:
                        return err.messages, 422
                else:
                    return "This request has not data",400
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")


@blp.route('/margaret/role/all', methods=['GET'])
@jwt_required()
def get_role_all():
    x=get_jwt()["jti"]
    # print(x)
    current_user = get_jwt_identity()

    data= RoleUserModel.query.filter(RoleUserModel.user_id== current_user).first()
    if data is None:
        abort(404,message="User,not found")
    # print(x==data.info1)
    if x!=data.jti:
        abort(401,message="unauthorized User")
   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(404,message="Role,not vaild ")
    
    if data2.active==True:
        get_data = RoleModel.query.order_by(asc(RoleModel.id)).all()
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                output = []
                for user in get_data:

                    output_data = {}
                    output_data['uid'] = user.uid
                    output_data['name'] = user.name
                    output_data['super_admin'] = user.super_admin
                    output_data['active'] = user.active
                    output_data['role'] = user.role
                    output_data['logs'] = user.logs
                    output.append(output_data)

                return jsonify({"data":output}),200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")


@blp.route('/margaret/role/<role_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(role_id):
    x=get_jwt()["jti"]
    # print(x)
    current_user = get_jwt_identity()

    data= RoleUserModel.query.filter(RoleUserModel.user_id== current_user).first()
    if data is None:
        abort(404,message="User,not found")
    # print(x==data.info1)
    if x!=data.jti:
        abort(401,message="unauthorized User")
   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(404,message="Role is not vaild ")
    
    if data2.active==True:
        get_data = RoleModel.query.filter_by(uid=role_id).first()
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                
                output_data = {}
                output_data['id'] = get_data.id
                output_data['uid'] = get_data.uid
                output_data['name'] = get_data.name
                output_data['super_admin'] = get_data.super_admin
                output_data['active'] = get_data.active
                output_data['create_at'] = get_data.create_at
                output_data['role'] = get_data.role
                output_data['logs'] = get_data.logs

                return jsonify(output_data),200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")


@blp.route('/margaret/role/status', methods=['PUT'])
@jwt_required()
def update_status_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
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
                if (request.data):
                    json_data=request.get_json()
                    # print(json_data)
            
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        request_data = role_update_status_schema.load(json_data)
                        # print(request_data['active'])
                        get_data = RoleModel.query.filter_by(uid=request_data['uid']).first()
                        create_at=datetime.now()
                        if request_data['active']==True:
                            
                            new_logs={
                                "admin": str(current_user),
                                "message": "role is actived",
                                "create_at": str(create_at)
                            }
                        else:
                            new_logs={
                                "admin": str(current_user),
                                "message": "role is deactived",
                                "create_at": str(create_at)
                            }
                        logs = []
                        logs.append(get_data.logs)
                        logs.append(new_logs)
                        logs_data=flatten_list_of_dicts(logs)
                        if get_data :
                            RoleModel.query.filter(RoleModel.uid==request_data['uid']).update({"active":request_data['active'],'logs':logs_data})
                            db.session.commit()

                            return {"message":"Update Succesfully"},201
                        abort(401,message="Role Name doesn't Match")
                    except ValidationError as err:
                        return err.messages, 422
                abort(400,message="This request has not data")
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

@blp.route('/margaret/role/update', methods=['PUT'])
@jwt_required()
def update_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
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
                if (request.data):
                    json_data=request.get_json()
                    # print(json_data)
            
                    if not json_data:
                        return {"message": "No input data provided"}, 400
                    try:
                        request_data = role_update_schema.load(json_data)
                        
                        get_data = RoleModel.query.filter_by(uid=request_data['uid']).first()
                        if get_data.super_admin==True:
                            abort(400,message="Super Admin not Editable")
                        create_at=datetime.now()
                        new_logs={
                            "admin": str(current_user),
                            "message": "role updated",
                            "create_at": str(create_at)
                        }
                        logs = []
                        logs.append(get_data.logs)
                        logs.append(new_logs)
                        logs_data=flatten_list_of_dicts(logs)
                        
                        if get_data :
                            RoleModel.query.filter(RoleModel.uid==request_data['uid']).update({"name":request_data['name'],"active":request_data['active'],
                            "role":{"tv_app_management":request_data['tv_app_management'],
                            "end_tv_app_user_management":request_data['end_tv_app_user_management'],
                            "app_management":request_data['app_management'],
                            "user_management":request_data['user_management']},"logs":logs_data})
                            db.session.commit()

                            return {"message":"Update Succesfully"},201
                        abort(401,message="Role Name doesn't Match")
                    except ValidationError as err:
                        return err.messages, 422
                abort(400,message="This request has not data")
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

@blp.route('/margaret/role/delete', methods=['DELETE'])
@jwt_required()
def delete_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.user_id== current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    role_id=request.args.get('id')
   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(404,message="Role,not vaild ")
    roles = RoleModel.query.filter(RoleModel.uid==role_id).first()
    if roles is None:
         abort(404,message="ID is not Found")
    if roles.super_admin==True:
        abort(400,message="Super Admin not Deletable")
    
    
    if data2.active==True:
    

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                
                role = RoleModel.query.filter_by(uid=role_id).first()
                if role is None:
                    abort(404,message="user id is not match")
                db.session.delete(role)
                db.session.commit()
                return jsonify({'message' : 'Role  deleted Succesfully!'}),201
                
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")





@blp.route('/margaret/role/helper', methods=['GET'])
@jwt_required()
def get_helper_role_all():
    x=get_jwt()["jti"]
    # print(x)
    current_user = get_jwt_identity()

    data= RoleUserModel.query.filter(RoleUserModel.user_id== current_user).first()
    # print(x==data.info1)
    if data is None:
        abort(404,message="User,not found")
    # print(x==data.info1)
    if x!=data.jti:
        abort(401,message="unauthorized User")

   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(404,message="Role,not vaild ")
    
    if data2.active==True:
        get_data = RoleModel.query.order_by(asc(RoleModel.id)).all()
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                output = []
                for user in get_data:

                    output_data = {}
                    output_data['uid'] = user.uid
                    output_data['name'] = user.name
                    output.append(output_data)

                return jsonify({"data":output}),200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

