from flask import Flask, render_template, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask import request
import hmac
import hashlib
import time
import os

app = Flask(__name__)
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
    form = verifyForm()

    return render_template('verify.html')
    username = request.get('username')
    #
    # stored_challenge = session.get('challenge')
    #
    # # 检查挑战是否有效
    # if not stored_challenge:
    #     return jsonify({'success': False, 'error': '挑战无效或已过期'}), 400
    # if data.get('challenge') != stored_challenge:
    #     return jsonify({'success': False, 'error': '挑战不匹配'}), 400

    # 示例验证逻辑（需替换为实际加密验证）


    # 清除已使用的挑战
    session.pop('challenge', None)

    if request.method == 'GET':
        # 显示验证页面（比如生物识别验证页面）
        return render_template('verify.html')

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
    data = f"{timestamp}:{nonce}"

    # 使用HMAC-SHA256签名
    signature = hmac.new(
        key=app.secret_key.encode('utf-8'),
        msg=data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    # 组合成挑战消息
    challenge = f"{data}:{signature}"

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