from dotenv import load_dotenv
load_dotenv()

import os
import base64
import hashlib
from collections import defaultdict
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, make_response, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from email_sender import send_email
from auth import (register_user, login_user, logout_user, get_user_by_token,
                 create_permission_request, get_permission_request, get_pending_permission_requests,
                 review_permission_request, verify_admin_credentials)
from middleware import token_required, login_required


def get_admin_id_int(admin_id_raw):
    """Convert MongoDB _id (string) or other ID to consistent integer for SQLite."""
    if admin_id_raw is None:
        return 1
    if isinstance(admin_id_raw, int):
        return admin_id_raw
    if isinstance(admin_id_raw, str):
        # Use deterministic hash (MD5) to convert string to integer
        # Take first 8 characters of hex digest and convert to int
        hash_obj = hashlib.md5(admin_id_raw.encode('utf-8'))
        hex_digest = hash_obj.hexdigest()
        # Convert first 8 hex chars to integer (max value: 0xFFFFFFFF = 4294967295)
        return int(hex_digest[:8], 16) % (10**9)  # Keep within reasonable range
    return 1


# ---------------------- CONFIG ----------------------
SECRET_KEY = os.environ.get('SECRET_KEY', 'replace-this-in-prod')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'replace-jwt-secret-in-prod')
TOKEN_SALT = 'phish-link-salt'
TOKEN_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

# Set JWT_SECRET_KEY for auth module
if not os.environ.get('JWT_SECRET_KEY'):
    os.environ['JWT_SECRET_KEY'] = JWT_SECRET_KEY

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# ---------------------- MODELS ----------------------
class UserInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), nullable=False, index=True)
    clicked_link = db.Column(db.Boolean, default=False)
    opened = db.Column(db.Boolean, default=False)
    trained = db.Column(db.Boolean, default=False)
    trained_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, nullable=False)  # Removed foreign key constraint

    def __repr__(self):
        return f"<UserInteraction {self.email} opened={self.opened} clicked={self.clicked_link} trained={self.trained}>"


class TrainingMaterial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    video_path = db.Column(db.String(500), nullable=True)
    doc_html = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<TrainingMaterial {self.title}>"


# Initialize databases
with app.app_context():
    db.create_all()
    # Initialize MongoDB for authentication
    try:
        from db import init_db
        init_db()
    except Exception as e:
        app.logger.warning(f"Could not initialize MongoDB: {e}. Authentication may not work without MongoDB.")


# <<< add this near the top of app.py, after your imports and before routes >>>

# Simple in-memory template registry (id -> template data).
# Later you can move these into DB (TrainingMaterial or new Template model).
TEMPLATES = {
    1: {
        "subject": "Important IT Security Notice",
        "heading": "IT Security: Action Required",
        "body": ("Our systems detected suspicious activity on your account. "
                 "Please verify your identity to avoid interruption."),
        "button_text": "Verify Now"
    },
    2: {
        "subject": "You've Won! Claim Your Prize",
        "heading": "Congratulations — You Won!",
        "body": ("You have been selected to receive a prize. Click below to claim "
                 "your gift and provide delivery details."),
        "button_text": "Claim Prize"
    },
    3: {
        "subject": "Bank Alert: Confirm Your Account",
        "heading": "Banking Security Notification",
        "body": ("We noticed unusual login attempts. Confirm your account details "
                 "immediately to secure your account."),
        "button_text": "Confirm Account"
    },
    4: {
        "subject": "Invoice: Payment Required",
        "heading": "Invoice Notice",
        "body": ("A new invoice is pending payment. Please review the invoice and "
                 "confirm payment instructions."),
        "button_text": "View Invoice"
    }
}

# data URI for a 1x1 transparent gif (used as harmless fallback for open_pixel)
TRANSPARENT_PIXEL = "data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs="






# ---------------------- ROUTES ----------------------

# ✅ Front Page (Landing)
@app.route('/')
def frontpage():
    return render_template('frontpage.html')


# ---------------------- AUTHENTICATION ROUTES ----------------------

# Login route - displays login form and handles POST requests
@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        login_data = {
            'email': request.form.get('email'),
            'password': request.form.get('password')
        }
        
        result = login_user(login_data)
        
        if 'error' in result:
            flash(result['error'], 'danger')
            return render_template('login_auth.html', error=result['error'])
        
        # Store token in session
        session['token'] = result['token']
        session['user'] = result['user']
        
        flash('Login successful!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('login_auth.html')


# Admin login route (alias for user_login for compatibility)
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return user_login()


# Registration route - redirects to permission verification for admin accounts
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    # Redirect to permission verification for admin registration
    return redirect(url_for('admin_permission'))


# Logout route
@app.route('/logout')
def logout():
    token = session.get('token')
    if token:
        logout_user(token)
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('frontpage'))

# Permission verification route
@app.route('/admin-permission', methods=['GET', 'POST'])
def admin_permission():
    if request.method == 'POST':
        admin_email = request.form.get('email')
        admin_password = request.form.get('password')
        
        # Check if admin exists
        from auth import get_db
        db = get_db()
        
        # Check if any admin exists
        admin_exists = db.users.find_one({'role': 'admin'})
        
        if not admin_exists:
            # No admin exists, allow direct registration
            return redirect(url_for('register_admin'))
        
        # Admin exists, verify credentials
        login_data = {
            'email': admin_email,
            'password': admin_password
        }
        
        result = login_user(login_data)
        
        if 'error' in result:
            flash('Invalid admin credentials', 'danger')
            return render_template('admin_permission.html')
        
        # Check if user is admin
        if result['user'].get('role') != 'admin':
            flash('User is not an admin', 'danger')
            return render_template('admin_permission.html')
        
        # Valid admin, allow registration
        session['permission_granted'] = True
        return redirect(url_for('register_admin'))
    
    return render_template('admin_permission.html')

# Admin registration route
@app.route('/register-admin', methods=['GET', 'POST'])
def register_admin():
    # Check if permission was granted or no admin exists
    from auth import get_db
    db = get_db()
    admin_exists = db.users.find_one({'role': 'admin'})
    
    if admin_exists and not session.get('permission_granted'):
        flash('Permission required to create admin account', 'warning')
        return redirect(url_for('admin_permission'))
    
    if request.method == 'POST':
        user_data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'password': request.form.get('password')
        }
        
        # Register as admin
        user_data['role'] = 'admin'
        result = register_user(user_data)
        
        if 'error' in result:
            flash(result['error'], 'danger')
            return render_template('register.html')
        
        # Clear permission flag
        session.pop('permission_granted', None)
        
        # Redirect to login page after successful registration
        flash('Admin account created successfully! Please login.', 'success')
        return redirect(url_for('user_login'))
    
    return render_template('register.html')

# Check permission status route
@app.route('/check-permission-status/<request_id>')
def check_permission_status(request_id):
    result = get_permission_request(request_id)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 404
    
    return jsonify({
        'status': result['request']['status'],
        'message': 'Your request is ' + result['request']['status']
    })

# Admin permission requests review route
@app.route('/admin/permission-requests')
@login_required
def admin_permission_requests():
    # Verify current user is admin
    token = session.get('token')
    user_result = get_user_by_token(token)
    
    if 'error' in user_result or user_result['user'].get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    result = get_pending_permission_requests()
    
    if 'error' in result:
        return render_template('admin_permission_requests.html', error=result['error'])
    
    return render_template('admin_permission_requests.html', requests=result['requests'])

# Review permission request route
@app.route('/review-permission-request', methods=['POST'])
@login_required
def review_permission_request_route():
    request_id = request.form.get('request_id')
    action = request.form.get('action')
    comments = request.form.get('comments')
    
    if not request_id or not action:
        flash('Invalid request', 'danger')
        return redirect(url_for('admin_permission_requests'))
    
    # Get current user ID
    token = session.get('token')
    user_result = get_user_by_token(token)
    
    if 'error' in user_result:
        flash('Session error', 'danger')
        return redirect(url_for('admin_permission_requests'))
    
    reviewer_id = user_result['user']['_id']
    
    result = review_permission_request(request_id, reviewer_id, action, comments)
    
    if 'error' in result:
        flash(result['error'], 'danger')
    else:
        flash(result['message'], 'success')
    
    return redirect(url_for('admin_permission_requests'))





# ✅ Admin Dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    # MongoDB uses _id, not id
    admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id')
    admin_id = get_admin_id_int(admin_id_raw) if admin_id_raw else None
    if admin_id:
        interactions = UserInteraction.query.filter_by(admin_id=admin_id).all()
    else:
        interactions = []
    total = len(interactions)
    opens = sum(1 for i in interactions if i.opened)
    clicks = sum(1 for i in interactions if i.clicked_link)
    trained = sum(1 for i in interactions if i.trained)
    
    # Get admin username from session
    admin_username = session.get('user', {}).get('username', 'Admin')
    
    return render_template('admin_dashboard.html',
                           total=total, opens=opens, clicks=clicks, trained=trained,
                           admin_username=admin_username)


# ✅ Template selection page (middle page)
@app.route('/select_template')
@login_required
def select_template():
    templates = [
        {
            "id": 1,
            "title": "Fake IT Security Alert",
            "desc": "Email pretending to be from IT asking user to reset password.",
            "preview": "Your account will be disabled. Reset password immediately."
        },
        {
            "id": 2,
            "title": "Prize / Gift Scam",
            "desc": "Claims the user won a reward and asks for details.",
            "preview": "Congrats! You have won a new iPhone 15. Claim within 24hrs!"
        },
        {
            "id": 3,
            "title": "Bank Account Warning",
            "desc": "Fake bank security alert requesting verification.",
            "preview": "Your bank account has been locked due to suspicious activity."
        },
        {
            "id": 4,
            "title": "Invoice Payment",
            "desc": "Fake invoice email asking user to check attached payment request.",
            "preview": "New invoice pending. Please confirm payment immediately."
        }
    ]
    return render_template("select_template.html", templates=templates)



# Launch page: optional ?template=ID
@app.route('/launch')
@login_required
def launch_page():
    # template_id may come from querystring (e.g. /launch?template=2)
    template_id = request.args.get('template', type=int) or None

    selected = None
    if template_id and template_id in TEMPLATES:
        selected = {"id": template_id, **TEMPLATES[template_id]}
    # render index.html (the send form). Pass selected template to allow preview + hidden field.
    return render_template('index.html', selected_template=selected)


# Send phishing email - uses template_id from JSON or form
@app.route('/send_phishing_email', methods=['POST'])
@login_required
def send_phishing_email():
    data = request.get_json() or {}
    # support JSON body or traditional form post
    to_email = data.get('email') or request.form.get('email')
    template_id = (data.get('template_id') or request.form.get('template_id'))
    try:
        template_id = int(template_id) if template_id is not None else None
    except (ValueError, TypeError):
        template_id = None

    if not to_email:
        return jsonify({"error": "Missing email"}), 400

    token = serializer.dumps(to_email, salt=TOKEN_SALT)
    # click link points to your tracking click endpoint
    click_link = url_for('track_click', token=token, _external=True)

    # Choose template (fallback to ID 1 if not provided)
    tpl = TEMPLATES.get(template_id) or TEMPLATES.get(1)

    subject = tpl.get('subject', 'Important Notice')
    # Render phishing email with template values
    body = render_template(
        'phishing_email.html',
        heading=tpl.get('heading'),
        body_text=tpl.get('body'),
        button_text=tpl.get('button_text', 'Open'),
        link=click_link,
        # we don't rely on server-side open tracking — provide harmless pixel
        open_pixel=TRANSPARENT_PIXEL
    )

    try:
        send_email(to_email, subject, body)
        
        # Always create a new interaction record for each email sent
        # This allows tracking multiple emails sent to the same address
        # MongoDB uses _id, not id. Convert to integer for SQLite compatibility
        admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id', 1)
        admin_id = get_admin_id_int(admin_id_raw)
        # Create new interaction for this email send
        interaction = UserInteraction(email=to_email, admin_id=admin_id)
        db.session.add(interaction)
        db.session.commit()
        
        return jsonify(message=f"Phishing email sent to {to_email}!", token=token)
    except Exception as e:
        app.logger.exception("Failed to send email")
        return jsonify(message=f"Failed to send email: {str(e)}"), 500



# ✅ Track clicks → Redirect to Training Page
@app.route('/track_click/<string:token>')
def track_click(token):
    try:
        email = serializer.loads(token, salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
    except SignatureExpired:
        return "This simulation link has expired.", 400
    except BadSignature:
        return "Invalid link.", 400

    # Find the most recent unclicked interaction for this email
    # This ensures each email sent gets tracked separately
    interaction = UserInteraction.query.filter_by(
        email=email, 
        clicked_link=False
    ).order_by(UserInteraction.created_at.desc()).first()
    
    # If no unclicked interaction exists, try the most recent one (in case all are already clicked)
    if interaction is None:
        interaction = UserInteraction.query.filter_by(email=email).order_by(UserInteraction.created_at.desc()).first()
    
    if interaction is None:
        # If no interaction exists at all, create one (shouldn't happen if email was sent properly)
        admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id', 1)
        admin_id = get_admin_id_int(admin_id_raw)
        interaction = UserInteraction(email=email, clicked_link=True, admin_id=admin_id)
        db.session.add(interaction)
        db.session.commit()
    elif not interaction.clicked_link:
        # Update the most recent unclicked interaction - preserve the original admin_id
        interaction.clicked_link = True
        db.session.commit()

    # Redirect user to the Training Module
    return redirect(url_for('training_page', token=token))


# ✅ Track email opens (via invisible pixel)
@app.route('/t/open')
def open_pixel():
    token = request.args.get('token')
    if not token:
        return _transparent_pixel_response()

    try:
        email = serializer.loads(token, salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
    except Exception:
        return _transparent_pixel_response()

    # Find the most recent unopened interaction for this email
    # This ensures each email sent gets tracked separately
    interaction = UserInteraction.query.filter_by(
        email=email, 
        opened=False
    ).order_by(UserInteraction.created_at.desc()).first()
    
    # If no unopened interaction exists, try the most recent one (in case all are already opened)
    if interaction is None:
        interaction = UserInteraction.query.filter_by(email=email).order_by(UserInteraction.created_at.desc()).first()
    
    if interaction is None:
        # If no interaction exists at all, create one (shouldn't happen if email was sent properly)
        admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id', 1)
        admin_id = get_admin_id_int(admin_id_raw)
        interaction = UserInteraction(email=email, opened=True, admin_id=admin_id)
        db.session.add(interaction)
        db.session.commit()
    elif not interaction.opened:
        # Update the most recent unopened interaction - preserve the original admin_id
        interaction.opened = True
        db.session.commit()

    return _transparent_pixel_response()


def _transparent_pixel_response():
    """Return a 1x1 transparent pixel for tracking email opens."""
    gif = base64.b64decode("R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs=")
    resp = make_response(gif)
    resp.headers.set('Content-Type', 'image/gif')
    resp.headers.set('Content-Length', len(gif))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


# ✅ Training Page → YouTube + Docs + Quiz
@app.route('/training/<string:token>')
def training_page(token):
    try:
        email = serializer.loads(token, salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
    except Exception:
        return "Invalid or expired training link.", 400

    # Fetch latest training material or fallback
    material = TrainingMaterial.query.order_by(TrainingMaterial.created_at.desc()).first()
    if material is None:
        material = TrainingMaterial(
            title="Phishing Awareness Essentials",
            description="Learn how to identify phishing attacks using these short videos and key practices.",
            doc_html="""
                <h6>Key Guidelines:</h6>
                <ul>
                    <li>Inspect sender email addresses carefully.</li>
                    <li>Hover over links before clicking.</li>
                    <li>Never share login credentials via email.</li>
                    <li>Report suspicious messages immediately.</li>
                </ul>
            """
        )

    # Find the most recent interaction for this email (should exist from when email was sent or clicked)
    interaction = UserInteraction.query.filter_by(email=email).order_by(UserInteraction.created_at.desc()).first()
    if interaction is None:
        # If no interaction exists, try to get admin_id from session, but this shouldn't happen
        # if email was sent properly. Default to 1 as fallback.
        admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id', 1)
        admin_id = get_admin_id_int(admin_id_raw)
        interaction = UserInteraction(email=email, clicked_link=True, admin_id=admin_id)
        db.session.add(interaction)
        db.session.commit()

    return render_template('training.html', token=token, material=material, email=email)


# ✅ Record Training Completion
@app.route('/training/complete', methods=['POST'])
def training_complete():
    data = request.get_json() or {}
    token = data.get('token')
    answers = data.get('answers')

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        email = serializer.loads(token, salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
    except Exception:
        return jsonify({"error": "Invalid token"}), 400

    # Find the most recent interaction for this email (should exist from when email was sent or clicked)
    interaction = UserInteraction.query.filter_by(email=email).order_by(UserInteraction.created_at.desc()).first()
    if interaction is None:
        # If no interaction exists, try to get admin_id from session, but this shouldn't happen
        # if email was sent properly. Default to 1 as fallback.
        admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id', 1)
        admin_id = get_admin_id_int(admin_id_raw)
        interaction = UserInteraction(email=email, clicked_link=True, trained=True, trained_at=datetime.utcnow(), admin_id=admin_id)
        db.session.add(interaction)
    else:
        # Update existing interaction - preserve the original admin_id
        interaction.trained = True
        interaction.trained_at = datetime.utcnow()
    db.session.commit()

    return jsonify({"message": "Training recorded", "email": email, "answers": answers}), 200


@app.route('/training')
def public_training():
    """Public access to training module (without token)"""
    material = TrainingMaterial.query.order_by(TrainingMaterial.created_at.desc()).first()
    if material is None:
        material = TrainingMaterial(
            title="Phishing Awareness Training",
            description="Learn to recognize phishing attempts through short videos and best practices.",
            doc_html="<ul><li>Never click unknown links.</li><li>Check the sender’s email carefully.</li><li>Report suspicious messages immediately.</li></ul>"
        )
    return render_template('training.html', token=None, material=material, email="Guest User")


# ✅ Report Page
@app.route('/report')
@login_required
def report():
    # MongoDB uses _id, not id
    admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id')
    admin_id = get_admin_id_int(admin_id_raw) if admin_id_raw else None
    if admin_id:
        interactions = UserInteraction.query.filter_by(admin_id=admin_id).order_by(UserInteraction.created_at.desc()).all()
    else:
        interactions = []
    total = len(interactions)
    opens = sum(1 for i in interactions if i.opened)
    clicks = sum(1 for i in interactions if i.clicked_link)
    trained = sum(1 for i in interactions if i.trained)
    return render_template('report.html',
                           interactions=interactions,
                           total=total, opens=opens, clicks=clicks, trained=trained)


# ✅ Rewards/Ranking Page - Rank employees by click count
@app.route('/rewards')
@login_required
def rewards():
    # MongoDB uses _id, not id
    admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id')
    admin_id = get_admin_id_int(admin_id_raw) if admin_id_raw else None
    
    if admin_id:
        # Get all interactions for this admin
        interactions = UserInteraction.query.filter_by(admin_id=admin_id).all()
        
        # Group by email and count clicks
        email_stats = defaultdict(lambda: {'clicks': 0, 'opens': 0, 'trained': 0, 'first_seen': None})
        
        for interaction in interactions:
            email = interaction.email
            if interaction.clicked_link:
                email_stats[email]['clicks'] += 1
            if interaction.opened:
                email_stats[email]['opens'] += 1
            if interaction.trained:
                email_stats[email]['trained'] += 1
            # Track earliest interaction
            if email_stats[email]['first_seen'] is None or interaction.created_at < email_stats[email]['first_seen']:
                email_stats[email]['first_seen'] = interaction.created_at
        
        # Convert to list and sort by clicks (ascending - fewer clicks = better rank)
        ranked_employees = []
        for email, stats in email_stats.items():
            ranked_employees.append({
                'email': email,
                'clicks': stats['clicks'],
                'opens': stats['opens'],
                'trained': stats['trained'],
                'first_seen': stats['first_seen']
            })
        
        # Sort by clicks ascending (fewer clicks = better), then by opens ascending, then by trained descending
        # Lower clicks = better security awareness = higher rank
        ranked_employees.sort(key=lambda x: (x['clicks'], x['opens'], -x['trained']))
        
        # Assign ranks (handle ties)
        # Rank 1 = best (fewest clicks), higher rank numbers = worse (more clicks)
        current_rank = 1
        for i, employee in enumerate(ranked_employees):
            if i > 0 and (ranked_employees[i-1]['clicks'] != employee['clicks'] or 
                         ranked_employees[i-1]['opens'] != employee['opens']):
                current_rank = i + 1
            employee['rank'] = current_rank
    else:
        ranked_employees = []
    
    return render_template('rewards.html', employees=ranked_employees)


# ---------------------- MAIN ----------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
