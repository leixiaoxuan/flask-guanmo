# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, make_response, render_template, flash, redirect, url_for, session, escape, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_assets import Environment, Bundle
from flask_bootstrap import Bootstrap
from flask_mail import Mail,Message
from app.database import db, bcrypt
from app.mail import mail
from app.mod_unauthenticated.controllers import unauthenticated
from app.mod_authenticated.controllers import authenticated
from app.mod_users.controllers import users, login_manager, csrf

import os

def create_app(config=None):

    app = Flask(__name__)
    bootstrap = Bootstrap(app)

    # 文件中读取配置
    if config is None:
        config = os.path.join(app.root_path,'config.cfg')

    app.config.from_pyfile(config)

    # Secret key .
    app.secret_key = app.config['SECRET_KEY']

    # 各种初始化哈
    mail.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    bcrypt.init_app(app)
    csrf.init_app(app)
    #bootstrap.init_app(app)
    # Web assets (js, less)
    assets = Environment(app)
    js = Bundle('js/main.js',
                filters='jsmin', output='gen/bundle.js')
    assets.register('js_all', js)

    # Automatically tear down SQLAlchemy
    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()

    @app.before_request
    def before_request():
        g.user = current_user

    def send_email(to, subject, template, **kwargs):
        msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                        sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
        msg.body = render_template(template + '.txt', **kwargs)
        msg.html = render_template(template + '.html', **kwargs)
        mail.send(msg)

    # 注册蓝本
    app.register_blueprint(unauthenticated)
    app.register_blueprint(authenticated)
    app.register_blueprint(users)

    return app
