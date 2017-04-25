# -*- coding: utf-8 -*-
import datetime
import hashlib
from flask import request
from flask import current_app
from flask_login import UserMixin,AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import db

ROLE_USER = 0
ROLE_ADMIN = 1


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), unique = True)
    email = db.Column(db.String(120), unique = True)
    pw_hash = db.Column(db.String(480))
    avatar_hash = db.Column(db.String(32))
    name = db.Column(db.String(240),default='')
    created_on = db.Column(db.DateTime,default= datetime.datetime.now)
    confirmed = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    last_seen = db.Column(db.DateTime(), default=datetime.datetime.now)

    posts = db.relationship('Post', backref='author', lazy='dynamic')
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))



    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()

        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    def __repr__(self):
        if self.name:
            return '<User %r>' % (self.name,)
        else:
            return '<User %r>' % (self.username,)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.pw_hash = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.pw_hash,password)

    # def is_authenticated(self):
    #     return True
    #
    # def is_active(self):
    #     return True
    #
    # def is_anonymous(self):
    #     return False
    #
    # def get_id(self):
    #     return self.id

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        db.session.commit()
        return True

    def ping(self):
        self.last_seen = datetime.datetime.utcnow()
        db.session.add(self)

    def change_email(self, new_email,token):
        if self.confirm(token):
            self.email = new_email
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
            db.session.add(self)
            return True
        return False

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py
        seed()
        for i in range(count):
                u = User(email=forgery_py.internet.email_address(),
                    username=forgery_py.internet.user_name(True),
                    password=forgery_py.lorem_ipsum.word(),
                    confirmed=True,
                    name=forgery_py.name.full_name(),
                    location=forgery_py.address.city(),
                    about_me=forgery_py.lorem_ipsum.sentence(),
                    member_since=forgery_py.date.date(True))
                db.session.add(u)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()

    def follow(self, user):
        pass

    def unfollow(self, user):
        pass

    def is_following(self, user):
        return False

    def is_followed_by(self, user):
        return False

class Follower(db.Model):
    __tablename__ = 'followers'
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    followed_id = db.Column(db.Integer, nullable=False)
    create_on = db.Column(db.DateTime, default=datetime.datetime.now)

class Following(db.Model):
    __tablename__ = 'Followings'
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    following_id = db.Column(db.Integer, nullable=False)
    create_on = db.Column(db.DateTime, default=datetime.datetime.now)

class AnonymousUser(AnonymousUserMixin):

    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

##########################################

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))

    def __init__(self, notice):
        self.notice = notice

    def __repr__(self):
        return '<notice: %r>' % self.notice



'''
关注用户 0b00000001（ 0x01） 关注其他用户
在他人的文章中发表评论 0b00000010（ 0x02） 在他人撰写的文章中发布评论
写文章 0b00000100（ 0x04） 写原创文章
管理他人发表的评论 0b00001000（ 0x08） 查处他人发表的不当评论
管理员权限 0b10000000（ 0x80） 管理网站

用户角色
匿名 0b00000000（ 0x00） 未登录的用户。在程序中只有阅读权限
用户 0b00000111（ 0x07） 具有发布文章、发表评论和关注其他用户的权限。这是新用户的默认角色
协管员 0b00001111（ 0x0f） 增加审查不当评论的权限
管理员 0b11111111（ 0xff） 具有所有权限，包括修改其他用户所属角色的权限

'''

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                    Permission.COMMENT |
                    Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                        Permission.COMMENT |
                        Permission.WRITE_ARTICLES |
                        Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
                role.permissions = roles[r][0]
                role.default = roles[r][1]
                db.session.add(role)
        db.session.commit()

class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.now)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py
        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                timestamp=forgery_py.date.date(True),
                author=u)
            db.session.add(p)
        db.session.commit()

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.now)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    object_type_id = db.Column(db.Integer, db.ForeignKey('object_types.id'))

class ObjectPictures(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    object_type = db.Column(db.Integer, nullable=True)
    object_id = db.Column(db.Integer, nullable=True)
    url =db.Column(db.String(256))

class ObjectTypes(db.Model):
    __tablename__ = 'object_types'
    id = db.Column(db.Integer, primary_key=True)
    disabled = db.Column(db.Boolean)
    name = db.Column(db.String(64), unique=True)
    created_on = db.Column(db.DateTime,default= datetime.datetime.now)
    last_modify = db.Column(db.DateTime,default= datetime.datetime.now)

    @staticmethod
    def generate_object_types():
        objectTypes = {1:'posts',
                       2:'comments',
                       3:'users',
                       4:'roles',
                       5:'follow'}
        for objectTypeId,objectTypeName in objectTypes.items():
            objectType = ObjectTypes(id=objectTypeId,name=objectTypeName)
            db.session.add(objectType)
        db.session.commit()

