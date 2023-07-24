from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask import jsonify,request
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from db import db
from models import RoleModel
import json
import uuid
from datetime import datetime
from marshmallow import ValidationError
from sqlalchemy.types import JSON
from flask_jwt_extended import create_access_token,  get_jwt,jwt_required,create_refresh_token,get_jwt_identity
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.dialects import postgresql
from sqlalchemy import select, func,asc
from schemas.role_schema import RoleViewSchema,role_create_schema,role_update_schema,role_update_status_schema,role_update_name_schema
from models import RoleUserModel
from sqlalchemy import asc,or_,and_
blp = Blueprint("Roles", "Roles", description="Operations on Roles")

@blp.route("/role/super-admin")
class Role(MethodView):
    def get(self):
        data= RoleModel.query.filter(RoleModel.super_admin==True).first()
        # datas= RoleModel.query.filter(and_(RoleModel.super_admin==False,RoleModel.super_admin==None)).first()
        uid=str(uuid.uuid4())
        # print(datas)
        if  data is None :

            role = RoleModel(name="Super Admin",uid='11223344',active=True,super_admin=True,create_at=datetime.utcnow(),
            role={"user_management" : 'a',"tv_app_management":'a',"app_management":'a',"end_tv_app_user_management":'a'})
            # role = RoleModel(name="Author",active=True,role={ "author_management":True})
            # role = RoleModel(name="Notice",active=True,role={ "notice_management":True})
        # example2 = Example(json_column={"key" : "newvalue", "myarray" : [23, 676, 45, 88, 99], "objects" : {"name" : "Brian"}})
            db.session.add(role)
            db.session.commit()
        else:
            abort(400,message="Super Admin Already Created")
       

        return " 1st Role Create succesfully",201

@blp.route('/v1/user-management/role/create', methods=['POST'])
@jwt_required()
def create_role():
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
                        request_data = role_create_schema.load(json_data)
                        # print(request_data["name"])
                        
                        get_data = RoleModel.query.filter_by(name=request_data['name']).first()
                        # print(data,'data')
                        if get_data:
                            return {"message": "Name Already Exist"}, 422
                
                        user_management=False
                        tv_app_management=False
                        app_management=False
                        end_tv_app_user_management=False
                       
                       
                        keys=request_data.keys()
                        for i in keys:
                
                            if i =='user_management':
                                user_management=request_data["user_management"]
                            elif i=='tv_app_management':
                                tv_app_management=request_data["tv_app_management"]
                            elif i=='app_management':
                                app_management=request_data["app_management"]
                            elif i=='end_tv_app_user_management':
                                end_tv_app_user_management=request_data["end_tv_app_user_management"]
                            
                            
                        # print(keys)

                        
                        role = RoleModel(uuid=uid,name=request_data['name'],super_admin=False,active=request_data['active'],create_at=datetime.utcnow(),role={"user_management" : user_management,
                        "tv_app_management":tv_app_management,"end_tv_app_user_management":end_tv_app_user_management,"app_management":app_management})
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

# @blp.route('/v1/user-management/role/update/all', methods=['PUT'])
# @jwt_required()
# def update_role():
#     x=get_jwt()["jti"]
#     current_user = get_jwt_identity()
#     data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
#     if data is None:
#         abort(404,message="User,not found")
#     if x!=data.jti:
#         abort(401,message="unauthorized User")
#     role_id=request.args.get('id')
   
#     data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
#     if data2 is None:
#         abort(401,message="Role,not vaild ")
#     roles = RoleModel.query.filter(RoleModel.uuid==role_id).first()
    
#     if roles.super_admin==True:
#         abort(400,message="Super Admin not Editable")
#     if data2.active==True:
    

#         if data2.role['user_management'] =='a':
    
#             if data.active==True:
#                 if (request.data):
#                     json_data=request.get_json()
#                     # print(json_data)
            
#                     if not json_data:
#                         return {"message": "No input data provided"}, 400
#                     try:
#                         request_data = role_update_schema_all.load(json_data)
#                         get_data = RoleModel.query.filter_by(uuid=role_id).first()
#                         if get_data :
#                             RoleModel.query.filter(RoleModel.uuid==role_id).update({"name":request_data['name'],"active":request_data['active'],
#                             "role":{"tv_app_management":request_data['tv_app_management'],
#                             "end_tv_app_user_management":request_data['end_tv_app_user_management'],
#                             "app_management":request_data['app_management'],
#                             "user_management":request_data['user_management']}})
#                             db.session.commit()

#                             return {"message":"Update Succesfully"},201
#                         abort(401,message="Role Name doesn't Match")
#                     except ValidationError as err:
#                         return err.messages, 422
#                 else:
#                     return {"message":"This request has not data"},400
                
                
#             abort(401,message="User is not active")

#         abort(401,message="This Role is not permitted for you")

#     abort(400,message="role is not active")

@blp.route('/v1/user-management/role/delete', methods=['DELETE'])
@jwt_required()
def delete_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    role_id=request.args.get('id')
   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    roles = RoleModel.query.filter(RoleModel.uuid==role_id).first()
    if roles is None:
         abort(400,message="ID is not Found")
    if roles.super_admin==True:
        abort(400,message="Super Admin not Deletable")
    
    
    if data2.active==True:
    

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                mak=RoleUserModel.query.filter(RoleUserModel.role==roles.name).all()


                RoleUserModel.query.filter(RoleUserModel.role==roles.name).delete()
                db.session.commit()
                
                role = RoleModel.query.filter_by(uuid=role_id).first()
                if role is None:
                    abort(400,message="Id is not match")
                db.session.delete(role)
                db.session.commit()
                return jsonify({'message' : 'Role  deleted Succesfully!'}),201
                
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

@blp.route('/v1/user-management/role/status', methods=['PUT'])
@jwt_required()
def update_status_role():
    x=get_jwt()["jti"]
    current_user = get_jwt_identity()
    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    if x!=data.jti:
        abort(401,message="unauthorized User")
    role_id=request.args.get('id')
    
    # print(role_name,"ffffffffffff")

    
   
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
                        request_data = role_update_status_schema.load(json_data)
                        # print(request_data['active'])
                        get_data = RoleModel.query.filter_by(uuid=role_id).first()
                       
                        if get_data :
                            RoleModel.query.filter(RoleModel.uuid==role_id).update({"active":request_data['active']})
                            db.session.commit()

                            return {"message":"Update Succesfully"},201
                        abort(401,message="Role Name doesn't Match")
                    except ValidationError as err:
                        return err.messages, 422
                else:
                    return {"message":"This request has not data"},400
                
                
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")


@blp.route('/v1/user-management/role/<role_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(role_id):
    x=get_jwt()["jti"]
    # print(x)
    current_user = get_jwt_identity()

    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    # print(x==data.info1)
    if x!=data.jti:
        abort(401,message="unauthorized User")
   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    
    if data2.active==True:
        get_data = RoleModel.query.filter_by(uuid=role_id).first()
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                
                output_data = {}
                output_data['id'] = get_data.id
                output_data['uuid'] = get_data.uuid
                output_data['name'] = get_data.name
                output_data['super_admin'] = get_data.super_admin
                output_data['active'] = get_data.active
                output_data['create_at'] = get_data.create_at
                output_data['role'] = get_data.role

                return jsonify(output_data),200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

@blp.route('/v1/user-management/role/all', methods=['GET'])
@jwt_required()
def get_role_all():
    x=get_jwt()["jti"]
    # print(x)
    current_user = get_jwt_identity()

    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    if data is None:
        abort(404,message="User,not found")
    # print(x==data.info1)
    if x!=data.jti:
        abort(401,message="unauthorized User")
   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    
    if data2.active==True:
        get_data = RoleModel.query.order_by(asc(RoleModel.id)).all()
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                output = []
                for user in get_data:

                    output_data = {}
                    output_data['uuid'] = user.uuid
                    output_data['name'] = user.name
                    output_data['super_admin'] = user.super_admin
                    output_data['active'] = user.active
                    output_data['role'] = user.role
                    output.append(output_data)

                return jsonify({"data":output}),200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

@blp.route('/v1/user-management/role/helper', methods=['GET'])
@jwt_required()
def get_helper_role_all():
    x=get_jwt()["jti"]
    # print(x)
    current_user = get_jwt_identity()

    data= RoleUserModel.query.filter(RoleUserModel.uid == current_user).first()
    # print(x==data.info1)
    if data is None:
        abort(404,message="User,not found")
    # print(x==data.info1)
    if x!=data.jti:
        abort(401,message="unauthorized User")

   
    data2=RoleModel.query.filter(RoleModel.uid == data.role_id).first()
    if data2 is None:
        abort(401,message="Role,not vaild ")
    
    if data2.active==True:
        get_data = RoleModel.query.order_by(asc(RoleModel.id)).all()
        if not get_data:
            return jsonify({'message' : 'No user found!'}),400

        if data2.role['user_management'] =='a':
    
            if data.active==True:
                output = []
                for user in get_data:

                    output_data = {}
                    output_data['uuid'] = user.uuid
                    output_data['name'] = user.name
                    output.append(output_data)

                return jsonify({"data":output}),200
            abort(401,message="User is not active")

        abort(401,message="This Role is not permitted for you")

    abort(400,message="role is not active")

