from datetime import datetime
from flask import Flask, json, request, jsonify
from flask.helpers import make_response
from flask_sqlalchemy import SQLAlchemy
import uuid, datetime
import jwt
from werkzeug.security import generate_password_hash, check_password_hash 

app = Flask(__name__)
#api = Api(app)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

db.create_all()



@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
def get_one_users(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'users': user_data})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json(force=True)
    print(data)

    #hashed_password = generate_password_hash(data['password'], method = 'sha256')
    hashed_password = generate_password_hash(data['password'], method='sha256')
    print(hashed_password+"this is the passwrd")

    #new_user = User(public_id=str(uuid.uuid4()), name=data["name"], password=hashed_password, admin=False)
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User Created'})

@app.route('/user/<public_id>', methods=['PUT'])
def promote_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:  #request params
        return make_response('Could not varify request param', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:  #database check
        return make_response('Could not varify in db', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    print(user.password)
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token})

    return make_response('Could not varify password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})    #password missmatch


if __name__=='__main__':
    app.run(debug=True)