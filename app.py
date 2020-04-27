from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer,String, Float, Boolean
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
import requests
from functools import wraps
app= Flask(__name__)
app.config['SECRET_KEY']='secretkey'
basedir = os.path.abspath(os.path.dirname(__file__)) #Where to store the file for the db (same folder as the running application)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir,'toDo.db') #initalized db

db=SQLAlchemy(app)
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

@app.cli.command('dbSeed')
def db_seed():
    hashed_password=generate_password_hash('password', method='sha256')
    testUser=User(public_id=str(uuid.uuid4()),
                             name='Bob',
                             password=hashed_password,
                             admin=True)
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')


class User(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50), unique=True)
    name=Column(String(50), unique=True)
    password=Column(String(80))
    admin=db.Column(Boolean)

class Todo(db.Model):
    id=Column(Integer, primary_key=True)
    text=Column(db.String(50))
    complete=Column(Boolean)
    user_id=Column(Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-tokens' in request.headers:
            token=request.headers['x-access-tokens']
        if not token:
            return jsonify(message='Token is missing'),401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify(message='Token is invalid'),401

        return f(current_user, *args, **kwargs)
    return decorated
#User Endpoints
@app.route('/user',methods= ['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify(message="You don't have the valid credentials")

    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        output.append(user_data)


    return jsonify(users=output)


@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.admin:
        return jsonify(message="You don't have the valid credentials")
    user=User.query.filter_by(public_id=public_id).first()

    if user:
        user_data={}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        return jsonify(user=user_data)
    else :
        return jsonify(message='User does not exist')

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify(message="You don't have the valid credentials")

    data=request.get_json()
    hashed_password=generate_password_hash(data['password'], method='sha256')

    new_user=User(public_id=str(uuid.uuid4()),
                             name=data['name'],
                             password=hashed_password,
                             admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message='User was Created')


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    if not current_user.admin:
       return jsonify(message="You don't have the valid credentials")
    user=User.query.filter_by(public_id=public_id).first()

    if user:
        user.admin=True
        db.session.commit()
        return jsonify(message="User has been promoted")
        return jsonify(message='User does not exist')
    else:
           return jsonify(message='User does not exist')


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify(message="You don't have the valid credentials")
    user=User.query.filter_by(public_id=public_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(message='User was deleted')
    else:
        return jsonify(message='User does not exist')

@app.route('/login')
def login():
    auth=request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})

    user=User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})
    if check_password_hash(user.password, auth.password):
        token=jwt.encode({'public_id': user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(token=token.decode('UTF-8'))#
    else:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos=Todo.query.filter_by(user_id=current_user.id).all()
    output=[]
    for todo in todos:
        todo_data={}
        todo_data['id']=todo.id
        todo_data['text']=todo.text
        todo_data['complete']=todo.complete
        output.append(todo_data)


    return jsonify(todos=output)

@app.route('/todo/<to_do_id>', methods =['GET'])
@token_required
def get_one_todo(current_user, to_do_id):
     todo=Todo.query.filter_by(id=to_do_id, user_id=current_user.id).first()
     if todo:
        todo_data={}
        todo_data['id']=todo.id
        todo_data['text']=todo.text
        todo_data['complete']=todo.complete
        return jsonify(todo=todo_data)
     else:
        return jsonify(message='To do does not exist')


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data=request.get_json()
    new_todo=Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify(message='Todo Created!')

@app.route('/todo/<to_do_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, to_do_id):
    todo=Todo.query.filter_by(id=to_do_id, user_id=current_user.id).first()

    if todo:
        todo.complete=True
        db.session.commit()
        return jsonify(message="Todo item has been complete")
    else:
         return jsonify(message='To do does not exist')



@app.route('/todo/<to_do_id>', methods=['DELETE'])
@token_required
def delete_to_do(current_user, to_do_id):
     todo=Todo.query.filter_by(id=to_do_id, user_id=current_user.id).first()
     if todo:
        db.session.delete(todo)
        db.session.commit()
        return jsonify(message="Todo item has been deleted")
     else:
        return jsonify(message='Todo does not exist')





if __name__ =='__main__':
    app.run(debug=True)

