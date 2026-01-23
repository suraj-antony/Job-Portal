from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import db, User, Job, Application

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
jwt = JWTManager(app)

# ---------- AUTH ----------
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already exists"}), 400

    user = User(
        name=data["name"],
        email=data["email"],
        password=generate_password_hash(data["password"]),
        role=data["role"]
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user.id))

    return jsonify({"access_token": token})


# ---------- JOBS ----------
@app.route("/jobs", methods=["POST"])
@jwt_required()
def create_job():
    user_id = int(get_jwt_identity())

    data = request.get_json()

    job = Job(
        title=data["title"],
        description=data["description"],
        company=data["company"],
        employer_id=user_id
    )
    db.session.add(job)
    db.session.commit()
    return jsonify({"message": "Job posted successfully"}), 201


@app.route("/jobs", methods=["GET"])
def list_jobs():
    jobs = Job.query.all()
    return jsonify([
        {
            "id": j.id,
            "title": j.title,
            "company": j.company
        }
        for j in jobs
    ])


# ---------- APPLY ----------
@app.route("/apply", methods=["POST"])
@jwt_required()
def apply_job():
    user_id = get_jwt_identity()
    data = request.get_json()

    application = Application(
        user_id=user_id,
        job_id=data["job_id"]
    )
    db.session.add(application)
    db.session.commit()
    return jsonify({"message": "Applied successfully"}), 201


with app.app_context():
    db.create_all()

print("JWT_SECRET_KEY =", app.config.get("JWT_SECRET_KEY"))


if __name__ == "__main__":
    app.run(debug=True)
