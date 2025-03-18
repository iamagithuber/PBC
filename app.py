from flask import Flask, render_template, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from flask_migrate import Migrate
from flask import request
import hmac
import hashlib
import time
import os
import base64
from nacl.public import PrivateKey, SealedBox
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from flask_cors import CORS


app = Flask(__name__)
CORS(app, supports_credentials=True)  # 允许跨域且携带 Cookie
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # 密码哈希
    pk_sig = db.Column(db.String(130), nullable=False)    # 签名公钥
    sk_enc = db.Column(db.String(64), nullable=False)     # 加密私钥db
    pk_enc = db.Column(db.String(130), nullable=False)    # 加密公钥



# 登录表单
class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    # password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

# 注册表单
class RegisterForm(FlaskForm):
    username = StringField('用户名', validators=[
        DataRequired(),
        Length(min=4, max=50)
    ])
    password = PasswordField('密码', validators=[
        DataRequired(),
        Length(min=6)
    ])

    confirm_password = PasswordField('确认密码',
        validators=[DataRequired(), EqualTo('password')])

    pk_sig = StringField('pk_sig', validators=[DataRequired()])
    sk_enc = StringField('sk_enc', validators=[DataRequired()])
    pk_enc = StringField('pk_enc', validators=[DataRequired()])

    submit = SubmitField('注册')

class verifyForm(FlaskForm):
    username = StringField('用户名', validators=[
        DataRequired(),
        Length(min=4, max=50)
    ])
    password = PasswordField('密码', validators=[
        DataRequired(),
        Length(min=6)
    ])

    encrypt_key = StringField('encrypt_key', validators=[DataRequired()])
    sign_key = StringField('sign_key', validators=[DataRequired()])
    public_key = StringField('public_key', validators=[DataRequired()])




# 创建数据库表
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        challenge = generate_challenge()
        session['challenge'] = challenge
        user = User.query.filter_by(username=form.username.data).first()
        # user需要转为json格式才能存储到session里
        # 这里等待修改，后端控制跳转，不能再让前端控制
        if user:
            return jsonify({
                'success': True,
                'challenge': challenge,
                'redirect': url_for('verify',_external=True)  # 添加跳转目标路由
            })
        else:
            return jsonify({'success': False}), 401

        # if user and check_password_hash(user.password, form.password.data):
        #     session['user'] = user.username
        #     flash('登录成功！', 'success')
        #     return redirect(url_for('home'))
        # else:
        #     flash('用户名或密码错误', 'danger')
    return render_template('login.html', form=form)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        # 显示验证页面（比如生物识别验证页面）
        return render_template('verify.html')



@app.route('/verify1', methods=['GET', 'POST'])
def verify1():
    challenge = session.get('challenge')
    data = request.get_json()
    encrypted_data = data.get('encryptedData')
    username = data.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        pk_sig = user.pk_sig
        sk_enc = user.sk_enc
        print("user has been found")
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        print("encrypted_data:", encrypted_data)
        print("encrypted_data_bytes:",encrypted_data_bytes)
        # 解密
        sk_enc_bytes = base64.b64decode(sk_enc)
        private_key = PrivateKey(sk_enc_bytes)
        sealed_box = SealedBox(private_key)
        decrypted_sigma = sealed_box.decrypt(encrypted_data_bytes)
        der_sign_hex = decrypted_sigma.hex()
        print("der_sign_hex:",der_sign_hex) # equal to derSign in verify.js
        # 将hex转为字节
        public_key_bytes = binascii.unhexlify(pk_sig)
        # 从字节加载公钥
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            public_key_bytes
        )
        # 转换DER签名到字节
        der_signature = bytes.fromhex(der_sign_hex)
        # 拼接验证消息->bytes格式
        raw_data = f"{username}{challenge}".encode("utf-8")

        try:
            # 验证签名
            public_key.verify(
                der_signature,
                raw_data,
                ec.ECDSA(hashes.SHA256())
            )
            session.pop('challenge', None)
            session.pop('username', None)
            return jsonify({'success': True})
        except InvalidSignature:
            return jsonify({"success": False, "error": "签名无效"}), 400
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    else:
        return jsonify({"success:": False, "error": "用户不存在"}), 400


@app.route('/user', methods=['GET', 'POST'])
def user ():
    return render_template('user.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            pk_sig=form.pk_sig.data,  # 签名公钥
            sk_enc=form.sk_enc.data,  # 加密私钥
            pk_enc=form.pk_enc.data,  # 加密公钥
        )
        db.session.add(new_user)
        db.session.commit()
        flash('注册成功，请登录！', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


def generate_challenge():
    # 生成时间戳和随机数
    timestamp = str(int(time.time()))
    nonce = os.urandom(16).hex()  # 生成16字节的随机数
    data = f"{timestamp}{nonce}"

    # 使用HMAC-SHA256签名
    signature = hmac.new(
        key=app.secret_key.encode('utf-8'),
        msg=data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    # 组合成挑战消息
    challenge = f"{data}{signature}"

    # 存储到Session供后续验证
    session['challenge_data'] = {
        'timestamp': timestamp,
        'nonce': nonce
    }
    return challenge

def verify_challenge(client_challenge):
    # 解析客户端挑战消息
    # 拆分客户都安发送的挑战消息
    try:
        timestamp, nonce, signature = client_challenge.split(':')
    except ValueError:
        return False

    # 检查时间戳有效性（例如5分钟内）
    if time.time() - int(timestamp) > 300:
        return False

    # 重新计算签名
    data = f"{timestamp}:{nonce}"
    expected_signature = hmac.new(
        key=app.secret_key.encode('utf-8'),
        msg=data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    # 安全比较签名
    if not hmac.compare_digest(signature, expected_signature):
        return False

    # 验证Session中的数据是否匹配
    stored_data = session.get('challenge_data')
    if not stored_data or stored_data['nonce'] != nonce or stored_data['timestamp'] != timestamp:
        return False

    return True


if __name__ == '__main__':
    app.run(debug=True)


