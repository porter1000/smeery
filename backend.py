from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import openai
import os

app = Flask(__name__, template_folder='')
CORS(app)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a more secure secret key
jwt = JWTManager(app)

# In-memory storage for users and progress (use a database in production)
users = {}
progress = {}

# Initialize the OpenAI client
openai.api_key = os.getenv("OPENAI_API_KEY")

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    if username in users:
        return jsonify({"msg": "User already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users[username] = {
        'password': hashed_password,
        'email': email,
        'first_name': first_name,
        'last_name': last_name
    }
    progress[username] = {"sat_progress": 0, "study_guides_completed": 0}  # Initialize progress

    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users or not bcrypt.check_password_hash(users[username]['password'], password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    return jsonify(access_token=access_token, refresh_token=refresh_token), 200

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token), 200

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    username = get_jwt_identity()
    user_info = users[username]
    return jsonify({
        "username": username,
        "email": user_info['email'],
        "first_name": user_info['first_name'],
        "last_name": user_info['last_name'],
        "progress": progress[username]
    }), 200

@app.route('/progress', methods=['POST'])
@jwt_required()
def update_progress():
    username = get_jwt_identity()
    data = request.get_json()
    progress_type = data.get('type')
    value = data.get('value')

    if progress_type not in progress[username]:
        return jsonify({"msg": "Invalid progress type"}), 400

    progress[username][progress_type] = value
    return jsonify({"msg": "Progress updated successfully"}), 200

@app.route('/ask', methods=['POST'])
@jwt_required()
def ask():
    data = request.json
    prompt = data.get('prompt', '')
    max_tokens = data.get('max_tokens', 150)
    temperature = data.get('temperature', 0.7)

    client = openai.ChatCompletion()
    try:
        response = client.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful tutor specialized in SAT prep, if it is a math problem that Desmos can solve, explain with Desmos BUT ONLY suggest Desmos for math. Never give a direct answer, always try and teach the concept. Never use more than 100 words."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature
        )
        answer = response['choices'][0]['message']['content']
        answer = answer.replace('\n', '<br>').replace('  ', '&nbsp;&nbsp;').strip()
        return jsonify({
            'response': answer
        })
    except Exception as e:
        print(f'Error: {str(e)}')
        return jsonify({'response': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
