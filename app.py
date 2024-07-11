from flask import request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
import secrets
from datetime import timedelta
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from models import User, Organisation, app, db, bcrypt
import os


migrate = Migrate(app=app, db=db)
expiration = timedelta(minutes=60)
jwt = JWTManager(app)

if not os.path.isfile('secret_key.txt'):
    secret_key = secrets.token_urlsafe(32)
    with open('secret_key.txt', 'w') as f:
        f.write(secret_key)
else:
    with open('secret_key.txt', 'r') as f:
        secret_key = f.read()

app.config['SECRET_KEY'] = secret_key
app.config['JWT_SECRET_KEY'] = secret_key
app.config['JWT_TOKEN_LOCATION'] = ['headers']


def validate_model(model):
    try:
        db.session.add(model)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        errors = []
        for err in e.orig.args:
            errors.append({"field": err.split()[0], "message": " ".join(err.split()[1:])})
        return jsonify({"errors": errors}), 422
    return  jsonify({"message": "User created successfully!"}), 201

@app.route("/auth/register", methods=["POST"])
def auth_register():
    try:
        data = request.get_json()
        firstName = data['first_name']
        lastName = data['last_name']
        email = data['email']
        password = data['password']
        phone = data['phone']

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        organisation_name = f"{firstName}'s Organisation"
        organisation = Organisation(name=organisation_name)
        
        db.session.add(organisation)
        db.session.commit()  

        user = User(first_name=firstName, 
                    last_name=lastName, 
                    email=email, 
                    password=hashed_password, 
                    phone=phone, 
                    organisation_id=organisation.org_id)
        
        validate_model(user)

        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity=email, expires_delta=expiration)

        return jsonify({
            "status": "success",
            "message": "Registration successful",
            "data": {
                "accessToken": access_token,
                "user": {
                    "userId": user.user_id,
                    "firstName": user.first_name,
                    "lastName": user.last_name,
                    "email": user.email,
                    "phone": user.phone,
                }
            }
        }), 201
    except:
        return jsonify({
            "status": "Bad request",
            "message": "Registration unsuccessful",
            "statusCode": 400})


@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"status": "Bad request", "message": "User not found", "statusCode": 404}), 404
    
    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=email, expires_delta=expiration)
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "data": {
                "accessToken": access_token,
                "user": {
                    "userId": user.user_id,
                    "firstName": user.first_name,
                    "lastName": user.last_name,
                    "email": user.email,
                    "phone": user.phone
                }
            }
        }), 200

    return jsonify({"status": "Bad request", 
                    "message": "Authentication failed", 
                    "statusCode": 401}), 401


@app.route("/api/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    email = get_jwt_identity()
    user = User.query.get(user_id)
    print('User', user)
    if user.email == email:
        return jsonify({
            "status": "success",
            "message": "User found",
            "data": {
                "userId": user.user_id,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "email": user.email,
                "phone": user.phone
            }
        }), 200
    return jsonify({"status": "Not found", "message": "User not found", "statusCode": 404}), 404

@app.route("/api/organisations", methods=["GET"])
@jwt_required()
def get_organisations():
    email = get_jwt_identity()
    organisations = Organisation.query.join(
        User).filter(User.email == email).all()
    return jsonify({
        "status": "success",
        "message": "Organisations found",
        "data": [{
            "orgId": organisation.org_id,
            "name": organisation.name,
            "description": organisation.description
        } for organisation in organisations]
    }), 200


@app.route("/api/organisations/<int:org_id>", methods=["GET"])
@jwt_required()
def get_organisation(org_id):
    organisation = Organisation.query.get(org_id)
    if organisation:
        return jsonify({
            "status": "success",
            "message": "Organisation found",
            "data": {
                "orgId": organisation.org_id,
                "name": organisation.name,
                "description": organisation.description
            }
        }), 200
    return jsonify({"status": "Not found", "message": "Organisation not found", "statusCode": 404}), 404


@app.route("/api/organisations", methods=["POST"])
@jwt_required()
def create_organisation():
    data = request.get_json()
    organisation = Organisation(name=data["name"], description=data["description"])
    db.session.add(organisation)
    db.session.commit()
    return jsonify({
        "status": "success",
        "message": "Organisation created successfully",
        "data": {
            "orgId": organisation.org_id,
            "name": organisation.name,
            "description": organisation.description
        }
    }), 201


@app.route("/api/organisations/<int:org_id>/users", methods=["POST"])
def add_user_to_organisation(org_id):
    data = request.get_json()
    user_id = data["user_id"]
    organisation = Organisation.query.get(org_id)
    user = User.query.get(user_id)
    if organisation and user:
        organisation.users.append(user)
        db.session.commit()
        return jsonify({"status": "success", "message": "User added to organisation successfully"}), 200
    return jsonify({"status": "Bad request", "message": "Client error", "statusCode": 400}), 400


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)