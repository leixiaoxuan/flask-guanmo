# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
from flask import Blueprint, request, make_response, render_template, flash, redirect, url_for, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect

from .models import User, ROLE_USER, ROLE_ADMIN,AnonymousUser,Permission,Role
from app.database import db, bcrypt
from .froms import LoginForm,RegistrationForm,EditProfileForm,EditProfileAdminForm
from ..mail import send_email
from app.decorators import admin_required, permission_required

users = Blueprint('users', __name__, url_prefix='/users')
csrf = CSRFProtect()

# 初始化 flask-login
login_manager = LoginManager()
login_manager.anonymous_user = AnonymousUser
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

# 把权限添加到上下文免得每次要传参。。
@users.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)

# 必须实现的一个回调函数
@login_manager.user_loader
def load_user(id):
        return User.query.get(int(id))

# 用户登录
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('authenticated.index'))
        flash('Invalid username or password.')
    return render_template('users/login.html', form=form)
#
# def login():
#     if request.method == 'GET':
#         return render_template('users/login.html')
#     if g.user is not None and g.user.is_authenticated:
#         return redirect(url_for('authenticated.index'))
#     username = request.form['username']
#     user = User.query.filter(User.username==username).first()
#     if user is None:
#         flash('No such user. Please try again')
#         return render_template('users/login.html')
#     pw_check = bcrypt.check_password_hash(user.pw_hash, request.form['password'])
#     if not pw_check:
#         flash('Incorrect password. Please try again')
#         return render_template('users/login.html')
#     login_user(user)
#     flash("Logged in successfully")
#     return redirect(url_for('authenticated.index'))

# 用户注册
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
        username=form.username.data,
        password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        login_user(user)
        send_email(user.email,'请您确认','users/email/confirm',user=user,token=token)
        flash('已发送邮件到您邮箱.')
        return redirect(url_for('unauthenticated.index'))
    return render_template('users/register.html', form=form)
    # if request.method == 'POSuT':
    #     username = request.form['username']
    #     if User.query.filter(User.username==username).first():
    #         flash('User already exists. Please log in.')
    #         return redirect(url_for('users.login'))
    #     pw_hash = bcrypt.generate_password_hash(request.form['password'])
    #     user = User(username=username, pw_hash=pw_hash)
    #     db.session.add(user)
    #     db.session.commit()
    #     flash('User successfully registered. Please log in.')
    #     return redirect(url_for('users.login'))
    # return render_template('users/register.html')

# 用户登出
@login_required
def logout():
    logged_out = logout_user()
    if logged_out:
        msg = u'已退出登录'
        flash(msg)
        return render_template('unauthenticated/index.html', msg=msg)
    return render_template('unauthenticated/index.html')

# 用户设置
@login_required
def settings():
    return render_template('users/settings.html')

# 用户确认
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('authenticated.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('unauthenticated.index'))

# 每次请求前运行，已认证用户更新最后浏览时间，检查认证用户是否确认，不确认的用户访问用户页返回未确认页面
@users.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
            and request.endpoint[:5] != 'users':
            #and request.endpoint != 'static':
            return redirect(url_for('users.unconfirmed'))

# 未认证页面
@users.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous() or current_user.confirmed:
        return redirect(url_for('unauthenticated.index'))
    return render_template('users/email/unconfirmed.html')

# 重新发送确认邮件
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, '请您确认',
        'users/email/confirm', user=current_user, token=token)

    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


def user(id):
    user = User.query.filter_by(id=id).first()
    if user is None:
        abort(404)
    return render_template('user.html', user=user)

@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash(u'编辑好了哈')
        return redirect(url_for('.user', id=current_user.id))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)

@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)

@login_required
@admin_required
def for_admins_only():
    return "For administrators!"

@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def for_moderators_only():
    return "For comment moderators!"

# users蓝本路由
users.add_url_rule('/admin/', 'admin', for_admins_only, methods=['GET', 'POST'])
users.add_url_rule('/moderator/', 'moderator', for_moderators_only, methods=['GET', 'POST'])

users.add_url_rule('/login/', 'login', login, methods=['GET', 'POST'])
users.add_url_rule('/register/', 'register', register, methods=['GET', 'POST'])
users.add_url_rule('/settings/', 'settings', settings)
users.add_url_rule('/logout/', 'logout', logout)
users.add_url_rule('/confirm/<token>','confirm',confirm)
users.add_url_rule('/confirm/','resend_confirmation',resend_confirmation)
users.add_url_rule('/unconfirm/','unconfirm',unconfirmed)
users.add_url_rule('/unconfirm/','unconfirm',unconfirmed)
users.add_url_rule('/<id>','user_detail',user)
users.add_url_rule('/edit/<int:id>','edit_profile',edit_profile)
users.add_url_rule('/adm-edit/<int:id>','edit_profile_admin',edit_profile_admin)