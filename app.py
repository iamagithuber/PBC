from flask import Flask, render_template, redirect, url_for, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

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
    password = PasswordField('密码', validators=[DataRequired()])
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
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user'] = user.username
            flash('登录成功！', 'success')
            return redirect(url_for('home'))
        else:
            flash('用户名或密码错误', 'danger')
    return render_template('login.html', form=form)

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


if __name__ == '__main__':
    app.run(debug=True)