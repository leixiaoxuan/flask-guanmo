# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
from flask_mail import Mail,Message
from flask import render_template
mail = Mail()

def send_email(to, subject, template, **kwargs):
    msg = Message('GM机车' + subject,
                    sender='GM Admin <tazxuan@163.com>', recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    #msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)