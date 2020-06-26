from flask import Flask, request, jsonify
import os
import uuid
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from model import *
app = Flask(__name__)
app.config['SECRET_KEY'] = ' 33084f87af6a610441082c51e0f9693f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:i200798@localhost/miniblog'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

@app.route('/user',methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],method='sha256')
    new_user = User(id=data['id'],public_id=str(uuid.uuid4()),name=data['name'],email=data['email'],password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'new user created with success'})

@app.route('/user',methods=['GET'])
def get_user():
    return jsonify({'message'})

if __name__ == '__main__':
    app.run(debug=True)