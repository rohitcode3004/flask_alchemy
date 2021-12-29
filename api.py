from datetime import datetime
from flask import Flask, json, request, jsonify
from flask.helpers import make_response
from flask_sqlalchemy import SQLAlchemy
import uuid, datetime
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
#api = Api(app)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

class Uploads(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            #print(token)
            #data = jwt.decode(token, app.config['SECRET_KEY'])
            data = jwt.decode(token, options={"verify_signature": False})
            #print(data)
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def save_to_db(f):
    def decorated(*args, **kwargs):
        returned_value = f(*args, **kwargs)

        if returned_value.status_code==201:
            #print('saved to db')
            token = request.headers['x-access-token']

            try:
                #print(token)
                #data = jwt.decode(token, app.config['SECRET_KEY'])
                data = jwt.decode(token, options={"verify_signature": False})
                #print(data)
                current_user = User.query.filter_by(public_id=data['public_id']).first()

                upload_data = Uploads(path=returned_value.path_info, user_id=current_user.id)
                db.session.add(upload_data)
                db.session.commit()

            except:
                return jsonify({'message' : 'Token is invalid'}), 401

        return returned_value

    return decorated

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that task'})
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
@token_required
def get_one_users(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that task'})

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
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that task'})

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
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that task'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that task'})

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


@app.route('/todos', methods=['GET'])
@token_required
def get_all_todos(current_user):

    todos = Todo.query.filter_by(user_id=current_user.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)

    return jsonify({'todos': output})

@app.route('/todo/<todos_id>', methods=['GET'])
@token_required
def get_one_todos(current_user, todos_id):

    todo = Todo.query.filter_by(id=todos_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No Todo found!'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify({'todos': todo_data})

@app.route('/todo', methods=['POST'])
@token_required
def create_todos(current_user):
    data = request.get_json(force=True)

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message' : 'New Todo Created'})

@app.route('/todo/<todos_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todos_id):

    todo = Todo.query.filter_by(id=todos_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    todo.complete = True
    db.session.commit()

    return jsonify({'message' : 'The todo has been completed!'})

@app.route('/todo/<todos_id>', methods=['DELETE'])
@token_required
def delete_todos(current_user, todos_id):

    todo = Todo.query.filter_by(id=todos_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : 'The todo has been deleted!'})


@app.route('/upload', methods=['POST'])
@token_required
@save_to_db
def upload_file(current_user):
    #check if the request has the file part
    if 'files[]' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp

    files = request.files.getlist('files[]')
    print(files)

    errors = {}
    success = False

    for file in files:

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            success = True
        else:
            errors[file.filename] = 'File type is not allowed'

    #if success and errors:
        #errors['message'] = 'File(s) successfully uploaded'
        #resp = jsonify(errors)
        #resp.status_code = 500
        #new_todo = Uploads(path=filename, user_id=current_user.id)
        #db.session.add(new_todo)
        #db.session.commit()
        #return resp
    if success:
        resp = jsonify({'message' : 'Files successfully uploaded'})
        resp.status_code = 201
        resp.path_info = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return resp
    else:
        resp = jsonify(errors)
        resp.status_code = 500
        return resp


if __name__=='__main__':
    app.run(debug=True)