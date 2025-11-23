import os
import jwt
import bcrypt
import datetime
import uuid
from db import get_db
from bson.objectid import ObjectId

# Super Admin Configuration (hardcoded for permission granting only)
SUPER_ADMIN_EMAIL = 'abdullahadmin@gmail.com'
SUPER_ADMIN_PASSWORD = 'Assignment4'

# User registration
def register_user(user_data):
    db = get_db()
    
    # Check if user already exists
    existing_user = db.users.find_one({'email': user_data.get('email')})
    if existing_user:
        return {'error': 'User with this email already exists'}
    
    # Hash the password
    hashed_password = bcrypt.hashpw(user_data.get('password').encode('utf-8'), bcrypt.gensalt())
    
    # Create new user
    new_user = {
        'username': user_data.get('username'),
        'email': user_data.get('email'),
        'password': hashed_password,
        'role': user_data.get('role', 'user'),  # Default to 'user' role
        'created_at': datetime.datetime.utcnow()
    }
    
    # Insert user into database
    result = db.users.insert_one(new_user)
    
    # Return user without password
    new_user['_id'] = str(result.inserted_id)
    new_user.pop('password', None)
    
    return {'user': new_user}

# User login
def login_user(login_data):
    db = get_db()
    
    # Block super admin from logging in (super admin is for permission only, not login)
    email = login_data.get('email', '').strip().lower()
    if email == SUPER_ADMIN_EMAIL.lower():
        return {'error': 'This account is for permission granting only and cannot be used for login'}
    
    # Find user by email
    user = db.users.find_one({'email': login_data.get('email')})
    if not user:
        return {'error': 'Invalid email or password'}
    
    # Check password
    if not bcrypt.checkpw(login_data.get('password').encode('utf-8'), user.get('password')):
        return {'error': 'Invalid email or password'}
    
    # Generate JWT token
    token = generate_token(user)
    
    # Return user without password
    user['_id'] = str(user['_id'])
    user.pop('password', None)
    
    return {'token': token, 'user': user}

# Generate JWT token
def generate_token(user):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'iat': datetime.datetime.utcnow(),
        'sub': str(user['_id'])
    }
    jwt_secret = os.getenv('JWT_SECRET_KEY', 'replace-jwt-secret-in-prod')
    return jwt.encode(
        payload,
        jwt_secret,
        algorithm='HS256'
    )

# Get user by token
def get_user_by_token(token):
    db = get_db()
    
    # Check if token is blacklisted
    blacklisted = db.blacklisted_tokens.find_one({'token': token})
    if blacklisted:
        return {'error': 'Token has been revoked'}
    
    try:
        # Decode token
        jwt_secret = os.getenv('JWT_SECRET_KEY', 'replace-jwt-secret-in-prod')
        payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        user_id = payload['sub']
        
        # Find user by ID
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return {'error': 'User not found'}
        
        # Return user without password
        user['_id'] = str(user['_id'])
        user.pop('password', None)
        
        return {'user': user}
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}

# Logout user
def logout_user(token):
    db = get_db()
    
    # Add token to blacklist
    db.blacklisted_tokens.insert_one({
        'token': token,
        'blacklisted_at': datetime.datetime.utcnow()
    })
    
    return {'message': 'Logged out successfully'}

def verify_super_admin(email, password):
    """
    Verify super admin credentials for permission granting only.
    Super admin cannot login - this is only for permission verification.
    """
    if email and email.strip().lower() == SUPER_ADMIN_EMAIL.lower():
        if password == SUPER_ADMIN_PASSWORD:
            return {'valid': True, 'message': 'Super admin verified'}
        else:
            return {'valid': False, 'error': 'Invalid super admin password'}
    return {'valid': False, 'error': 'Invalid super admin email'}

# Permission request functions
def create_permission_request(request_data):
    db = get_db()
    
    # Check if there's at least one admin in the system
    admin_count = db.users.count_documents({'role': 'admin'})
    if admin_count == 0:
        # First admin can be created without permission
        return {'skip_permission': True}
    
    # Check if email already has a pending request
    existing_request = db.permission_requests.find_one({
        'email': request_data.get('email'),
        'status': 'pending'
    })
    if existing_request:
        return {'error': 'A permission request for this email is already pending'}
    
    # Create permission request
    request_id = str(uuid.uuid4())
    permission_request = {
        'request_id': request_id,
        'username': request_data.get('username'),
        'email': request_data.get('email'),
        'password': bcrypt.hashpw(request_data.get('password').encode('utf-8'), bcrypt.gensalt()),
        'requested_role': 'admin',
        'status': 'pending',
        'created_at': datetime.datetime.utcnow(),
        'reviewed_by': None,
        'reviewed_at': None,
        'reviewer_comments': None
    }
    
    result = db.permission_requests.insert_one(permission_request)
    
    return {'request_id': request_id, 'message': 'Permission request submitted successfully'}

def get_permission_request(request_id):
    db = get_db()
    
    request = db.permission_requests.find_one({'request_id': request_id})
    if not request:
        return {'error': 'Permission request not found'}
    
    # Remove sensitive data
    request.pop('password', None)
    request['_id'] = str(request['_id'])
    
    return {'request': request}

def get_pending_permission_requests():
    db = get_db()
    
    requests = list(db.permission_requests.find({'status': 'pending'}).sort('created_at', -1))
    
    # Remove sensitive data and convert IDs
    for request in requests:
        request.pop('password', None)
        request['_id'] = str(request['_id'])
    
    return {'requests': requests}

def review_permission_request(request_id, reviewer_email, reviewer_password, action, comments=None):
    """
    Review permission request - ONLY super admin can approve/reject requests.
    Regular admins cannot review permission requests.
    """
    # Verify that the reviewer is the super admin
    super_admin_verify = verify_super_admin(reviewer_email, reviewer_password)
    if not super_admin_verify.get('valid'):
        return {'error': 'Only super admin can review permission requests. ' + super_admin_verify.get('error', 'Invalid credentials')}
    
    db = get_db()
    
    # Get the permission request
    request = db.permission_requests.find_one({'request_id': request_id})
    if not request:
        return {'error': 'Permission request not found'}
    
    if request['status'] != 'pending':
        return {'error': 'Permission request has already been reviewed'}
    
    if action == 'approve':
        # Create the user
        new_user = {
            'username': request['username'],
            'email': request['email'],
            'password': request['password'],
            'role': 'admin',
            'created_at': datetime.datetime.utcnow(),
            'permission_request_id': request_id
        }
        
        try:
            result = db.users.insert_one(new_user)
            
            # Update permission request status
            db.permission_requests.update_one(
                {'request_id': request_id},
                {
                    '$set': {
                        'status': 'approved',
                        'reviewed_by': SUPER_ADMIN_EMAIL,
                        'reviewed_at': datetime.datetime.utcnow(),
                        'reviewer_comments': comments
                    }
                }
            )
            
            return {'message': 'Permission request approved and user created successfully', 'user_id': str(result.inserted_id)}
            
        except Exception as e:
            return {'error': f'Failed to create user: {str(e)}'}
    
    elif action == 'reject':
        # Update permission request status
        db.permission_requests.update_one(
            {'request_id': request_id},
            {
                '$set': {
                    'status': 'rejected',
                    'reviewed_by': SUPER_ADMIN_EMAIL,
                    'reviewed_at': datetime.datetime.utcnow(),
                    'reviewer_comments': comments
                }
            }
        )
        
        return {'message': 'Permission request rejected'}
    
    else:
        return {'error': 'Invalid action. Must be "approve" or "reject"'}

def verify_admin_credentials(username, password):
    db = get_db()
    
    # Find admin by username
    admin = db.users.find_one({'username': username, 'role': 'admin'})
    if not admin:
        return {'error': 'Invalid admin credentials'}
    
    # Check password
    if not bcrypt.checkpw(password.encode('utf-8'), admin.get('password')):
        return {'error': 'Invalid admin credentials'}
    
    return {'admin': {'_id': str(admin['_id']), 'username': admin['username'], 'email': admin['email']}}