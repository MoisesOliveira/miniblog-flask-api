from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from datetime import datetime
from app import db

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50),unique=True)
    email = db.Column(db.String(80),unique=True)
    name = db.Column(db.String(150))
    password = db.Column(db.String(80))

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String(350))
    created_at = db.Column(db.DateTime,default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',backref=db.backref('user',lazy=True))

class Likes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer,db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    post = db.relationship('Post',backref=db.backref('post-like',lazy=True))
    user = db.relationship('User',backref=db.backref('user-like',lazy=True))

class Comments(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    post_id = db.Column(db.Integer,db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    post = db.relationship('Post',backref=db.backref('post-comment',lazy=True))
    user = db.relationship('User',backref=db.backref('user-comment',lazy=True))
    content = db.Column(db.String(175))

