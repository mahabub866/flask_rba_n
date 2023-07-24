from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager,decode_token
import secrets
from db import db
import os
from flask_cors import CORS
from flask_caching import Cache
from dotenv import load_dotenv
import psycopg2
# last e install dibo
from flask_migrate import Migrate
from blocklist import BLOCKLIST
from sqlalchemy import asc,or_,desc

from resources.role import blp as RoleBlueprint
from resources.role_user import blp as RoleUserBlueprint

from datetime import datetime, timedelta
import uuid
from models import BlockModel,RoleUserModel

from dotenv import load_dotenv
import os

load_dotenv()

url=os.getenv("db_url")

config_cache = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300
}

def create_app(db_url=None):
    app = Flask(__name__)
    CORS(app)
    # CORS(app, origins=['http://192.168.60.196/'], methods=['GET', 'POST'], allow_headers=['Content-Type'])
    load_dotenv()
    app.config.from_mapping(config_cache)
    cache = Cache(app)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Add Management API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/docs"
    app.config[
        "OPENAPI_SWAGGER_UI_URL"
    ] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    # app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///data.db")
    # url=os.getenv("DATABASE_URL")
    # connection=psycopg2.connect(url)
    # app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:password@localhost:5432/Demo"
    # app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:password@localhost:5432/Demo"
    app.config['SQLALCHEMY_DATABASE_URI'] = url
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:017%40admin@localhost:3306/add_management'
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://amimaa:Mahabub866!@localhost:3306/amima'
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5432/book_demo'
    # app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:password@localhost:5432/e_books"
    # app.config["SQLALCHEMY_DATABASE_URI"] = connection
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

# image upload support
    UPLOAD_FOLDER = 'static/uploads'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    # app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    #  this code must be written this place
    migrate = Migrate(app, db)

    api = Api(app)

    app.config["JWT_SECRET_KEY"] = os.getenv("AUTHJWT_SECRET_KEY")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=4000)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=4000)
    # app.config["JWT_SECRET_KEY"] = secrets.SystemRandom().getrandbits(128)
    jwt = JWTManager(app)

    

# 
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        block_count=BlockModel.query.filter(BlockModel.user_id == jwt_payload["sub"]).count()
        if block_count >=10:
            delete_token= BlockModel.query.filter(BlockModel.user_id == jwt_payload["sub"]).order_by(asc(BlockModel.create_at)).first()
            db.session.delete(delete_token)
            db.session.commit()
        block_token=BlockModel.query.filter(BlockModel.jti==jwt_payload["jti"]).first()
        if block_token is not None:
            return 'Token Block'
        main=RoleUserModel.query.filter(RoleUserModel.uid==jwt_payload["sub"]).first()
        # user_main=UserModel.query.filter(UserModel.uid==jwt_payload["sub"]).first()
        user_main=None
        if main  is None and user_main is None:
            return 'Token Block'
        if main is None and user_main:
            decode_value_user=decode_token(user_main.token)
            if decode_value_user['jti']!=jwt_payload["jti"]:
                return 'Token Block'
        if main and user_main is None:
            decode_value=decode_token(main.token)
            if decode_value['jti']!=jwt_payload["jti"]:
                return 'Token Block'


        # return jwt_payload["jti"] in BLOCKLIST


    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        

        return (
            jsonify(
                {"description": "The token has been revoked."}
            ),
            401,
        )

    # @jwt.additional_claims_loader
    # def add_claims_to_jwt(identity):
    #     if identity == 1:
    #         return {"is_admin": True}
    #     return {"is_admin": False}
        
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        # print(jwt_payload,".............././sa time")
        return (
            jsonify({"message": "The token has expired.", "error": "token_expired"}),
            401,
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify(
                {"message": "Signature verification failed.", "error": "invalid_token"}
            ),
            401,
        )
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {
                    "description": "The token is not fresh.",
                    "error": "fresh_token_required",
                }
            ),
            401,
        )
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {
                    "description": "Request does not contain an access token.",
                    "error": "authorization_required",
                }
            ),
            401,
        )
 


   
    with app.app_context():
        db.create_all()

    api.register_blueprint(RoleBlueprint)
    api.register_blueprint(RoleUserBlueprint)

    # api.register_blueprint(WeekVideosBlueprint)
    # api.register_blueprint(WeekImagesBlueprint)
    # api.register_blueprint(ReelImagesBlueprint)
    # api.register_blueprint(ReelVideosBlueprint)
    # api.register_blueprint(AppControlBlueprint)
    # api.register_blueprint(UserBlueprint)
    # api.register_blueprint(FaqBlueprint)
    # api.register_blueprint(OtpBlueprint)
    # api.register_blueprint(FaqUserBlueprint)
    # api.register_blueprint(BookDownloadBlueprint)
    # api.register_blueprint(FavouriteBlueprint)
    # api.register_blueprint(RatingBlueprint)
    # api.register_blueprint(CommentBlueprint)
    # api.register_blueprint(BookUserBlueprint)
    # api.register_blueprint(TestBlueprint)

    return app