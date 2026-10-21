from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import secrets

app = Flask(__name__)
# 密钥从环境变量 JWT_SECRET_KEY 读取；未设置时生成随机密钥（重启后已签发 token 失效，仅适合实验）
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY") or secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lab.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

# 用户数据表，使用ORM防护SQL注入
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

# 创建数据库与测试账号 admin / Admin123!
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        hash_pw = bcrypt.hashpw(b"Admin123!", bcrypt.gensalt())
        new_user = User(username="admin", password_hash=hash_pw.decode("utf-8"))
        db.session.add(new_user)
        db.session.commit()

# 接口1：POST /auth/login 用户登录获取JWT
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        token = create_access_token(identity=username)
        return jsonify(access_token=token), 200
    return jsonify(msg="Bad username or password"), 401

# 接口2：GET /api/data 需要JWT鉴权，受保护接口
@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_data():
    current_user = get_jwt_identity()
    # 简单输出转义，防御XSS
    safe_user = str(current_user).replace("<","&lt;").replace(">","&gt;")
    resp = {
        "user": safe_user,
        "data_list": ["item1","item2","item3"]
    }
    return jsonify(resp)

# 接口3：自己新增接口 GET /api/profile 获取当前登录用户资料
@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    u = get_jwt_identity()
    safe_u = str(u).replace("<","&lt;").replace(">","&gt;")
    return jsonify({"username": safe_u, "role":"user"})

if __name__ == "__main__":
    # debug 模式通过环境变量 FLASK_DEBUG=1 开启，默认关闭（生产环境必须关闭，避免 Werkzeug 调试器 RCE 风险）
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")