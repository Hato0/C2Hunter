# -*- encoding: utf-8 -*-
from WebInterface import db
import ipaddress
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import DateTime


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    notificationContent = db.Column(db.String(10000))
    time = db.Column(DateTime(timezone=True))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ipAddress = db.Column(db.String(10000))
    osAndVersion = db.Column(db.String(10000))
    hostname = db.Column(db.String(10000))
    compromissionLevel = db.Column(db.String(10000))
    initialAccessMethode = db.Column(db.String(10000))
    softInvetory = db.Column(db.String(10000))
    contactUrl = db.Column(db.String(10000))
    compromisedDate = db.Column(db.String(10000))
    lastContact = db.Column(db.String(10000))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    profilPicturePath = db.Column(db.String(1500))
    notification = db.relationship('Notification')
