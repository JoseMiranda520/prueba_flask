from flask_marshmallow import Marshmallow
# flask imports
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
from jsonschema import ValidationError

#setting

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fsdfsdcvssSSDS4r5desfgv.dfd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Django9090*@localhost/prueba'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

#models

class People(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identification = db.Column(db.String(15), unique=True)
    name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    age = db.Column(db.String(10))


    def __init__(self, identification, name, last_name, age):
        self.identification = identification
        self.name = name
        self.last_name = last_name
        self.age = age

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(200))

with app.app_context():
    db.create_all()

class PeopleSchema(ma.Schema):
    class Meta:
        fields = ('id', 'identification', 'name',  'last_name' , 'age')


people_schema = PeopleSchema()
peoples_schema = PeopleSchema(many=True)

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # validate jwt in header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token no in header
        if not token:
            return jsonify({'message' : 'Token is required'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated


# endpoint to get list users
@app.route('/users', methods =['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email
        })
  
    return jsonify({'users': output})

# endpoint for logging user in
@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.form
  
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
  
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

# signup endpoint
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
    if data.get('name') == None or data.get('name') == '' or data.get('email') == '' or data.get('email') == None or data.get('password') == None or data.get('password') == '':# or data.get('email') not in data or data.get('password') not in data:
        return make_response("ERROR: fields: 'name', 'email' and 'password' are required", 401)
  
    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')
  
    # checking for existing user
    user = User.query\
        .filter_by(email = email)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)

# endpoint for add people
@app.route('/add_people', methods=['POST'])
@token_required
def create_people(current_user):
    #Check fields
    data=request.json
    if 'identification' not in data or data.get('identification') == '' or 'name' not in data or data.get('name') == '' or 'last_name' not in data or data.get('last_name') == '' or 'age' not in data or data.get('age') == 'age':
        return make_response("ERROR: fields: 'name', 'last_name' and 'age' are required", 401)

    #Check if the person exists
    identification_s = request.json['identification']
    validate_identification = People.query.filter_by(identification = identification_s).first()
    if validate_identification:
        return make_response("warning: this document number already exists", 200)

    name = request.json['name']
    last_name = request.json['last_name']
    age = request.json['age']
    #save person
    try:
        new_people = People(identification_s, name, last_name, age)
        db.session.add(new_people)
        db.session.commit()
        return people_schema.jsonify(new_people)
    except Exception as e:
        return jsonify('Error interno: ' + str(e)), 500

# endpoint to get list people
@app.route('/get_all_people', methods=['GET'])
@token_required
def get_all_people(current_user):
    try:
        get_all_people = People.query.all()
        result = peoples_schema.dump(get_all_people)
        return jsonify(result)
    except Exception as e:
        return jsonify('Error interno: ' + str(e)), 500

# endpoint to search for a person through their document number
@app.route('/search_people', methods=['POST'])
@token_required
def search_people(current_user):
    data=request.json
    #Check field
    if 'identification_search' not in data or data.get('identification_search') == '':
        return make_response("ERROR: field: 'name', 'identification_search' is required", 401)

    identification_search = request.json['identification_search']
    try:
        #find cc
        people = People.query.filter_by(identification = identification_search).first()
        return people_schema.jsonify(people)
    except Exception as e:
        return jsonify('Error interno: ' + str(e)), 500

# endpoint to update people by their document number
@app.route('/update_people', methods=['PUT'])
@token_required
def update_people(current_user):
    data=request.json
    #Check fields
    if 'identification_update' not in data or data.get('identification_update') == '':
        return make_response("ERROR: field: 'identification_update' is required", 401)
    
    if 'name' not in data and data.get('name') == '' and 'last_name' not in data and data.get('last_name') == '' and 'age' not in data and data.get('age') == 'age':
        return make_response("ERROR: fields: 'name', 'last_name' and 'age' are required", 401)

    identification_update = request.json['identification_update']
    try:
        #Update Person
        people = People.query.filter_by(identification = identification_update).first()
        name = request.json['name']
        last_name = request.json['last_name']
        age = request.json['age']
        people.name = name
        people.last_name = last_name
        people.age = age
        db.session.commit()
        return people_schema.jsonify(people)
    except Exception as e:
        return jsonify('Error interno: ' + str(e)), 500

# endpoint to delete people by their document number
@app.route('/delete_people', methods=['DELETE'])
@token_required
def delete_people(current_user):
    data=request.json
    #Check fields
    if 'identification_delete' not in data or data.get('identification_delete') == '':
        return make_response("ERROR: field: 'identification_delete' is required", 401)

    identification_del = request.json['identification_delete']

    try:
        #deleted
        people = People.query.filter_by(identification = identification_del).first()
        db.session.delete(people)
        db.session.commit()
        return make_response("mgs: DELETED", 201)
    except Exception as e:
        return jsonify('Error interno: ' + str(e)), 500


#welcome endpoint
@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Welcome, please register at http://localhost:5000/signup POST method'})



if __name__ == "__main__":
    app.run(debug=True)