from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager


load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

user_org = db.Table("users_organisations",
            db.Column("usersColumn", db.Integer, db.ForeignKey("user_table.user_id")),
            db.Column("orgsColumn", db.Integer, db.ForeignKey("org_table.org_id"))
         )

class User(db.Model):
    __tablename__ = 'user_table'
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    users = db.relationship('Organisation', secondary=user_org, backref='organisation')

    def __repr__(self):
        return f"<User: {self.user_id}. {self.first_name} {self.last_name} - Email: {self.email}, Phone{self.phone}>"

class Organisation(db.Model):
    __tablename__ = "org_table"
    org_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    

    def __repr__(self):
        return f"<Organisation: {self.org_id}. {self.name} {self.description}>"