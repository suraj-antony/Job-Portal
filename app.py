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
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    required_fields = ["name", "email", "password", "role"]
    for field in required_fields:
        if field not in data or not str(data[field]).strip():
            return jsonify({"error": f"Field '{field}' is required and cannot be empty"}), 400

    role = data["role"].strip().lower()
    if role not in ["candidate", "employer"]:
        return jsonify({"error": "Role must be either 'candidate' or 'employer'"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already exists"}), 400

    user = User(
        name=data["name"],
        email=data["email"],
        password=generate_password_hash(data["password"]),
        role=role
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    required_fields = ["email", "password"]
    for field in required_fields:
        if field not in data or not str(data[field]).strip():
            return jsonify({"error": f"Field '{field}' is required"}), 400

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

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.role != "employer":
        return jsonify({"error": "Unauthorized: Only employers can post jobs"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400

    required_fields = ["title", "description", "company"]
    for field in required_fields:
        if field not in data or not str(data[field]).strip():
            return jsonify({"error": f"Field '{field}' is required and cannot be empty"}), 400

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
    user_id = int(get_jwt_identity())

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.role != "candidate":
        return jsonify({"error": "Unauthorized: Only candidates can apply for jobs"}), 403

    data = request.get_json()
    if not data or "job_id" not in data:
        return jsonify({"error": "Field 'job_id' is required"}), 400

    try:
        job_id = int(data["job_id"])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid job_id format"}), 400

    # Job existence check
    job = Job.query.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    # Duplicate check
    existing_application = Application.query.filter_by(user_id=user_id, job_id=job_id).first()
    if existing_application:
        return jsonify({"error": "You have already applied for this job"}), 400

    application = Application(
        user_id=user_id,
        job_id=job_id
    )
    db.session.add(application)
    db.session.commit()
    return jsonify({"message": "Applied successfully"}), 201


with app.app_context():
    db.create_all()

print("JWT_SECRET_KEY =", app.config.get("JWT_SECRET_KEY"))


if __name__ == "__main__":
    app.run(debug=True)
