from flask import Flask, request, jsonify, make_response,session
import os
import uuid
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from model import *
import jwt
import datetime
from functools import wraps
from flask_cors import CORS
from random import randint
app = Flask(__name__)
app.config['SECRET_KEY'] = ' 33084f87af6a610441082c51e0f9693f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:i200798@localhost/miniblog'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['CORS_HEADERS'] = 'Content-Type'

db = SQLAlchemy(app)
CORS(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message':'Token is missing. No access'}),401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid. No access'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/login',methods=['POST'])
def login():
    try:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})

        user = User.query.filter_by(name=auth.username).first()
        session['id'] = user.id
        session['public_id'] = user.public_id
        
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required"'})
    except:
        return jsonify({'message': 'something went wrong. Try again'}),401

@app.route('/register',methods=['POST'])
def get_information():
    try:
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'],method='sha256')
        new_user = User(id=data['id'],public_id=str(uuid.uuid4()),name=data['name'],email=data['email'],password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'new user created with success'})
    except:
        return jsonify({'message': 'something went wrong'})
    

@app.route('/users',methods=['GET'])
@token_required
def get_user(public_id):
    users = User.query.all()
    #users = db.session.query(User,Post).outerjoin(Post,User.id == Post.user_id).all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['email'] = user.email
        user_data['id'] = user.id
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user',methods=['GET'])
@token_required
def get_one_user(public_id):
    user = User.query.filter_by(public_id=session['public_id']).first()
    
    if not user:
        return jsonify({'message':'Not found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    return jsonify({'user': user_data})
    
@app.route('/post',methods=['POST'])
@token_required
def post(public_id):
    data = request.get_json()
    new_post = Post(id=data['id'],content=data['content'],user_id=session['id']) 
    db.session.add(new_post)
    db.session.commit()
    return jsonify({'post': data})

@app.route('/<post_id>/comment',methods=['POST'])
@token_required
def comment(public_id,post_id):
    data = request.get_json()
    user_id = session['id']
    new_comment = Comments(id=data['id'],post_id=post_id,user_id=user_id,content=data['content'])
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({'comment': data})
if __name__ == '__main__':
    app.run(debug=True)