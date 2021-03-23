"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Contact
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import datetime

## Security Suite
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.url_map.strict_slashes = False

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)
jwt = JWTManager(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/register', methods=['POST'])
def register():
    email = request.json.get("email", None)
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not email:
        return jsonify({"msg": "Email is required"}), 400
    if not username:
        return jsonify({"msg": "Username is required"}), 400
    if not password:
        return jsonify({"msg": "Password is required"}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"msg": "Username  already exists"}), 400

    user = User(email=email, username=username, password=generate_password_hash(password), is_active=True)
    db.session.add(user)
    db.session.commit()

    return jsonify({"msg": "User successfully registered"}),200

@app.route('/login', methods=['POST'])
def login():
    # make sure request is a json
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    # get email and password from request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # if params are empty, return a 400
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    # try to find user
    try:
        user = User.query.filter_by(username=username).first()
        if user.validate(password):
            # if user is validated (password is correct), return the token
            expires = datetime.timedelta(days=7)
            response_msg = {
                "user": user.serialize(),
                'token': create_access_token(identity=username,expires_delta=expires),
                "expires_at": expires.total_seconds()*1000 
            }
            status_code = 200
        else:
            raise Exception('Failed to login. Check your username and password.')
    # catch the specific exception and store in var
    except Exception as e:
        response_msg = {
            'msg': str(e),
            'status': 401
        }
        status_code = 401
    
    return jsonify(response_msg), status_code

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify({
        "logged_in_as": current_user,
        "msg": "Access Granted to Private route"
    }), 200

@app.route('/agenda', methods=['GET'])
def get_all_agenda():
    contact = Contact.query.all() #way to get all the contacts
    seri_contact= []
    for person in contact:
        seri_contact.append(person.serialize())
    print(contact)
    return jsonify(seri_contact), 200

@app.route('/add', methods=['POST'])
def add_contact():
    body = request.get_json()
    contact = Contact(full_name=body['full_name'], email=body['email'], address=body['address'], phone=body['phone'], status=body['status'])
    db.session.add(contact)
    db.session.commit()
    print(contact)
    return jsonify(contact.serialize()), 200

@app.route('/delete/<int:id>', methods=['DELETE'])
def delete_contact(id):
    contact = Contact.query.get(id)
    if contact is None:
        raise APIException('User not found', status_code=404)
    db.session.delete(contact)
    db.session.commit()
    response_body = {
        "msg": "Hello, you just deleted a contact"
    }
    return jsonify(response_body), 200

@app.route('/delete', methods=['DELETE'])
def delete_all_contacts():
    contacts = Contact.query.all()
    for contact in contacts:
        db.session.delete(contact)
    db.session.commit()
    response_body = {
        "msg": "Hello, you just deleted all contacts"
    }
    return jsonify(response_body), 200

@app.route('/update/<int:id>', methods=['PUT'])
def update_contact(id):
    body = request.get_json()
    contact = Contact.query.get(id)
    if contact is None:
        raise APIException('User not found', status_code=404)

    if "full_name" in body:
        contact.full_name = body["full_name"]
    if "email" in body:
        contact.email = body["email"]
    if "address" in body:
        contact.address = body['address']
    if "phone" in body:
        contact.phone = body['phone']
    if "status" in body:
        contact.status = body['status']
    db.session.commit()
    return jsonify(contact.serialize()), 200

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
