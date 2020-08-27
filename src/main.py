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
#from models import Person

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

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
    contact = Contact(full_name=body['full_name'], email=body['email'], address=body['address'], phone=body['phone'])
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
    db.session.commit()
    return jsonify(contact.serialize()), 200

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
