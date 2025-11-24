from dotenv import load_dotenv
load_dotenv()

import os
import base64
import hashlib
from urllib.parse import urljoin
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
                 verify_admin_credentials, verify_super_admin, SUPER_ADMIN_EMAIL)
from middleware import token_required, login_required
from db import get_db

# ---------------------- CONFIG ----------------------
SECRET_KEY = os.environ.get('SECRET_KEY', 'replace-this-in-prod')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'replace-jwt-secret-in-prod')
TOKEN_SALT = 'phish-link-salt'
TOKEN_MAX_AGE = 60 * 60 * 24 * 30  # 30 days
EXTERNAL_BASE_URL = os.environ.get('EXTERNAL_BASE_URL', '').rstrip('/')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

# Set JWT_SECRET_KEY for auth module
if not os.environ.get('JWT_SECRET_KEY'):
    os.environ['JWT_SECRET_KEY'] = JWT_SECRET_KEY

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---------------------- HELPERS ----------------------
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


def get_current_user_id():
    """Return the logged-in Mongo user id (string) if available."""
    user = session.get('user') or {}
    user_id = user.get('_id') or user.get('id')
    if user_id is None:
        return None
    return str(user_id)


def build_external_url(endpoint, **values):
    """
    Build absolute URLs for emails. Uses EXTERNAL_BASE_URL if provided,
    otherwise falls back to Flask's _external URL generation.
    """
    if EXTERNAL_BASE_URL:
        relative = url_for(endpoint, _external=False, **values)
        return urljoin(EXTERNAL_BASE_URL + '/', relative.lstrip('/'))
    return url_for(endpoint, _external=True, **values)


def _get_user_template_collection():
    """Return MongoDB collection used for per-user templates."""
    try:
        mongo_db = get_db()
    except Exception as exc:
        app.logger.warning("MongoDB unavailable for templates: %s", exc)
        return None
    return mongo_db.user_templates


def get_user_template_override(user_id, template_id):
    """Fetch a user's customized template override, if it exists."""
    if not user_id:
        return None
    collection = _get_user_template_collection()
    if collection is None:
        return None
    doc = collection.find_one({'user_id': user_id, 'template_id': template_id})
    if not doc:
        return None
    doc.pop('_id', None)
    return doc


def get_user_template_overrides_map(user_id):
    """Return all overrides for a user as a dict keyed by template_id."""
    if not user_id:
        return {}
    collection = _get_user_template_collection()
    if collection is None:
        return {}
    overrides = {}
    for doc in collection.find({'user_id': user_id}):
        template_id = doc.get('template_id')
        if template_id is not None:
            doc = dict(doc)
            doc.pop('_id', None)
            overrides[template_id] = doc
    return overrides


def save_user_template_override(user_id, template_id, template_data):
    """Persist a user's customized template into MongoDB."""
    collection = _get_user_template_collection()
    if collection is None:
        raise ConnectionError("MongoDB is unavailable for saving templates")
    payload = {
        'user_id': user_id,
        'template_id': template_id,
        'title': template_data.get('title'),
        'subject': template_data.get('subject'),
        'heading': template_data.get('heading'),
        'body': template_data.get('body'),
        'button_text': template_data.get('button_text'),
        'preview': template_data.get('preview'),
        'updated_at': datetime.utcnow()
    }
    collection.update_one(
        {'user_id': user_id, 'template_id': template_id},
        {'$set': payload},
        upsert=True
    )


def compute_preview(body_text, subject):
    """Helper to build preview text consistent across stores."""
    if body_text:
        return body_text[:200]
    return subject

# data URI for a 1x1 transparent gif (used as harmless fallback for open_pixel)
TRANSPARENT_PIXEL = "data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs="

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

# Persistent Template model for email templates
class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # displayed on card
    subject = db.Column(db.String(300), nullable=False)
    heading = db.Column(db.String(300), nullable=True)
    body = db.Column(db.Text, nullable=True)
    button_text = db.Column(db.String(100), nullable=True)
    preview = db.Column(db.String(500), nullable=True)  # optional short preview
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def as_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "subject": self.subject,
            "heading": self.heading,
            "body": self.body,
            "button_text": self.button_text,
            "preview": self.preview
        }

    def __repr__(self):
        return f"<Template {self.title}>"

# ---------------------- IN-MEMORY TEMPLATES (fallback) ----------------------
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

# ---------------------- TEMPLATE DB HELPERS ----------------------
def seed_default_templates():
    """
    If no templates are present in DB, insert the ones from the in-memory TEMPLATES dict.
    This runs on startup so the user sees the same 4 templates to start.
    """
    existing = Template.query.count()
    if existing == 0:
        for tid, tpl in TEMPLATES.items():
            t = Template(
                id=tid,
                title=tpl.get("heading") or tpl.get("subject") or f"Template {tid}",
                subject=tpl.get("subject", ""),
                heading=tpl.get("heading", ""),
                body=tpl.get("body", ""),
                button_text=tpl.get("button_text", "Open"),
                preview=(tpl.get("body")[:200] if tpl.get("body") else tpl.get("subject"))
            )
            db.session.add(t)
        db.session.commit()

def get_template_by_id(template_id, user_id=None):
    """
    Return a template dict searching DB first, then fall back to in-memory TEMPLATES dict.
    """
    try:
        tid = int(template_id)
    except Exception:
        return None

    t = Template.query.get(tid)
    template_dict = None
    if t:
        template_dict = t.as_dict()
    # fallback to in-memory
    elif tid in TEMPLATES:
        template_dict = TEMPLATES[tid].copy()
        template_dict['id'] = tid
        template_dict.setdefault('heading', '')
        template_dict.setdefault('body', '')
        template_dict.setdefault('button_text', 'Open')

    if not template_dict:
        return None

    template_dict.setdefault('id', tid)
    template_dict.setdefault('title', template_dict.get('heading') or template_dict.get('subject'))
    template_dict.setdefault('preview', compute_preview(template_dict.get('body'), template_dict.get('subject')))

    if user_id:
        override = get_user_template_override(user_id, tid)
        if override:
            for key in ('title', 'subject', 'heading', 'body', 'button_text', 'preview'):
                if override.get(key) is not None:
                    template_dict[key] = override[key]

    return template_dict

# ---------------------- DB INIT & SEED ----------------------
with app.app_context():
    db.create_all()
    # Initialize MongoDB for authentication (if available)
    try:
        from db import init_db
        init_db()
    except Exception as e:
        app.logger.warning(f"Could not initialize MongoDB: {e}. Authentication may not work without MongoDB.")
    # Seed templates if DB empty
    try:
        seed_default_templates()
    except Exception as e:
        app.logger.warning(f"Failed to seed templates: {e}")

# ---------------------- ROUTES ----------------------

# Front Page (Landing)
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

        # Verify super admin credentials (only super admin can grant permissions)
        result = verify_super_admin(admin_email, admin_password)

        if not result.get('valid'):
            flash('Invalid super admin credentials. Only the super admin can grant permissions to create new admin accounts.', 'danger')
            return render_template('admin_permission.html')

        # Super admin verified, allow registration
        session['permission_granted'] = True
        session['super_admin_verified'] = True
        flash('Super admin verified. You can now create a new admin account.', 'success')
        return redirect(url_for('register_admin'))

    return render_template('admin_permission.html')

# Admin registration route
@app.route('/register-admin', methods=['GET', 'POST'])
def register_admin():
    # Check if super admin permission was granted
    # Always require super admin permission (even if no admin exists)
    if not session.get('permission_granted') or not session.get('super_admin_verified'):
        flash('Super admin permission required to create admin account', 'warning')
        return redirect(url_for('admin_permission'))

    if request.method == 'POST':
        user_data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'password': request.form.get('password')
        }

        # Prevent registering the super admin email as a regular admin
        if user_data.get('email', '').strip().lower() == SUPER_ADMIN_EMAIL.lower():
            flash('Cannot register the super admin email as a regular admin account.', 'danger')
            return render_template('register.html')

        # Register as admin
        user_data['role'] = 'admin'
        result = register_user(user_data)

        if 'error' in result:
            flash(result['error'], 'danger')
            return render_template('register.html')

        # Clear permission flags
        session.pop('permission_granted', None)
        session.pop('super_admin_verified', None)

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

# Admin permission requests review route - DISABLED: Only super admin can grant permissions
@app.route('/admin/permission-requests')
@login_required
def admin_permission_requests():
    flash('Permission request review is only available to super admin. Regular admins cannot review permission requests.', 'warning')
    return redirect(url_for('admin_dashboard'))

# Review permission request route - DISABLED: Only super admin can review
@app.route('/review-permission-request', methods=['POST'])
def review_permission_request_route():
    flash('Only super admin can grant permissions. Please use the admin permission page.', 'warning')
    return redirect(url_for('admin_permission'))

# ---------------------- ADMIN / DASHBOARD ----------------------

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

    admin_username = session.get('user', {}).get('username', 'Admin')

    return render_template('admin_dashboard.html',
                           total=total, opens=opens, clicks=clicks, trained=trained,
                           admin_username=admin_username)


# ---------------------- TEMPLATE SELECTION / LAUNCH / EDIT ----------------------

@app.route('/select_template')
@login_required
def select_template():
    # Load all templates from DB ordered by id
    templates_db = Template.query.order_by(Template.id).all()
    templates = []
    for t in templates_db:
        templates.append({
            "id": t.id,
            "title": t.title or t.subject,
            "desc": (t.subject[:120] + '...') if t.subject and len(t.subject) > 120 else (t.subject or ""),
            "preview": t.preview or (t.body[:160] if t.body else "")
        })
    # If DB has no templates (should be seeded), fall back to in-memory
    if not templates:
        for tid, tpl in TEMPLATES.items():
            templates.append({
                "id": tid,
                "title": tpl.get('heading') or tpl.get('subject'),
                "desc": (tpl.get('subject')[:120] + '...') if tpl.get('subject') and len(tpl.get('subject')) > 120 else tpl.get('subject'),
                "preview": tpl.get('body')[:160] if tpl.get('body') else tpl.get('subject')
            })
    user_id = get_current_user_id()
    if user_id:
        overrides = get_user_template_overrides_map(user_id)
        for tpl in templates:
            override = overrides.get(tpl["id"])
            if override:
                tpl["title"] = override.get("title", tpl["title"])
                subject_for_desc = override.get("subject") or tpl.get("desc") or ""
                tpl["desc"] = (subject_for_desc[:120] + '...') if subject_for_desc and len(subject_for_desc) > 120 else subject_for_desc
                tpl["preview"] = override.get("preview", tpl["preview"])
    return render_template("select_template.html", templates=templates)

# Launch page: optional ?template=ID
@app.route('/launch')
@login_required
def launch_page():
    # template_id may come from querystring (e.g. /launch?template=2)
    template_id = request.args.get('template', type=int) or None

    selected = None
    user_id = get_current_user_id()
    if template_id:
        tpl = get_template_by_id(template_id, user_id=user_id)
        if tpl:
            selected = {"id": tpl.get("id"), "subject": tpl.get("subject"), "heading": tpl.get("heading"), "body": tpl.get("body"), "button_text": tpl.get("button_text")}
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
    click_link = build_external_url('track_click', token=token)

    # Choose template (DB -> in-memory fallback -> default 1)
    tpl = None
    user_id = get_current_user_id()
    if template_id:
        tpl = get_template_by_id(template_id, user_id=user_id)
    if not tpl:
        tpl = get_template_by_id(1, user_id=user_id) or TEMPLATES.get(1)

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

# Edit template page (GET shows form, POST saves)
@app.route('/template/edit/<int:template_id>', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    # Ensure base template exists for fallback / display
    tpl = Template.query.get(template_id)
    if tpl is None:
        mem = TEMPLATES.get(template_id)
        if mem:
            tpl = Template(
                id=template_id,
                title=mem.get("heading") or mem.get("subject") or f"Template {template_id}",
                subject=mem.get("subject", ""),
                heading=mem.get("heading", ""),
                body=mem.get("body", ""),
                button_text=mem.get("button_text", "Open"),
                preview=(mem.get("body")[:200] if mem.get("body") else mem.get("subject"))
            )
            db.session.add(tpl)
            db.session.commit()
        else:
            flash("Template not found.", "danger")
            return redirect(url_for('select_template'))

    user_id = get_current_user_id()
    if not user_id:
        flash("You must be logged in to edit templates.", "danger")
        return redirect(url_for('select_template'))

    if request.method == 'POST':
        form = request.form or request.get_json() or {}
        # Start from merged template (base + override) so unspecified fields stay
        merged_template = get_template_by_id(template_id, user_id=user_id)
        if not merged_template:
            flash("Template not found.", "danger")
            return redirect(url_for('select_template'))

        updated_template = {
            'title': form.get('title') or merged_template.get('title'),
            'subject': form.get('subject') or merged_template.get('subject'),
            'heading': form.get('heading') or merged_template.get('heading'),
            'body': form.get('body') or merged_template.get('body'),
            'button_text': form.get('button_text') or merged_template.get('button_text')
        }
        updated_template['preview'] = compute_preview(updated_template['body'], updated_template['subject'])
        try:
            save_user_template_override(user_id, template_id, updated_template)
        except Exception as exc:
            flash(f"Failed to save template: {exc}", "danger")
            return redirect(url_for('select_template'))
        flash("Template saved for your account.", "success")
        return redirect(url_for('select_template'))

    template_data = get_template_by_id(template_id, user_id=user_id)
    if not template_data:
        flash("Template not found.", "danger")
        return redirect(url_for('select_template'))
    return render_template('edit_template.html', template=template_data)

# Lightweight API endpoint to update template via AJAX/PUT
@app.route('/api/template/<int:template_id>', methods=['PUT'])
@login_required
def api_update_template(template_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    base_tpl = Template.query.get(template_id)
    if base_tpl is None and template_id not in TEMPLATES:
        return jsonify({"error": "Template not found"}), 404
    data = request.get_json() or {}
    merged_template = get_template_by_id(template_id, user_id=user_id)
    if not merged_template:
        return jsonify({"error": "Template not found"}), 404
    updated_template = {
        'title': data.get('title', merged_template.get('title')),
        'subject': data.get('subject', merged_template.get('subject')),
        'heading': data.get('heading', merged_template.get('heading')),
        'body': data.get('body', merged_template.get('body')),
        'button_text': data.get('button_text', merged_template.get('button_text'))
    }
    updated_template['preview'] = compute_preview(updated_template['body'], updated_template['subject'])
    try:
        save_user_template_override(user_id, template_id, updated_template)
    except Exception as exc:
        return jsonify({"error": f"Failed to update template: {exc}"}), 500
    refreshed = get_template_by_id(template_id, user_id=user_id)
    return jsonify({"message": "Template updated", "template": refreshed}), 200

# ---------------------- TRACKING / PIXEL / TRAINING ----------------------

# Track clicks → Redirect to Training Page
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

# Track email opens (via invisible pixel)
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

# Training Page → YouTube + Docs + Quiz
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
        # If no interaction exists, default to admin from session or 1
        admin_id_raw = session.get('user', {}).get('_id') or session.get('user', {}).get('id', 1)
        admin_id = get_admin_id_int(admin_id_raw)
        interaction = UserInteraction(email=email, clicked_link=True, admin_id=admin_id)
        db.session.add(interaction)
        db.session.commit()

    return render_template('training.html', token=token, material=material, email=email)

# Record Training Completion
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
        # Default to admin id 1 if session not available
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

# Report Page
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

# Rewards/Ranking Page - Rank employees by click count
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
        ranked_employees.sort(key=lambda x: (x['clicks'], x['opens'], -x['trained']))

        # Assign ranks (handle ties)
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)