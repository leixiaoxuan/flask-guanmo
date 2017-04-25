# -*- coding: utf-8 -*-
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms import ValidationError
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from .models import User,Role


class LoginForm(FlaskForm):
    email = StringField(u'电子邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField(u'密码', validators=[DataRequired()])
    remember_me = BooleanField(u'记住我?')
    submit = SubmitField(u'登录')


class RegistrationForm(FlaskForm):
    email = StringField(u'电子邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField(u'用户名', validators=[DataRequired(), Length(1, 64), Regexp('[A-Za-z0-9_\u4e00-\u9fa5]*', 0,
                                                                                     u'汉字数字字母下划线')])
    password = PasswordField(u'密码', validators=[
        DataRequired(), EqualTo(u'password2', message=u'两次输入密码不一样.')])
    password2 = PasswordField(u'确认密码', validators=[DataRequired()])
    submit = SubmitField(u'注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱已被注册')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(u'用户名已经存在.')


class EditProfileForm(FlaskForm):
    name = StringField(u'真实姓名，', validators=[Length(0, 64)])
    location = StringField(u'位置', validators=[Length(0, 64)])
    about_me = TextAreaField(u'自我介绍哈！')
    submit = SubmitField(u'编辑')


class EditProfileAdminForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired, Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        DataRequired, Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                            'Usernames must have only letters,numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
