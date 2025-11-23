from functools import wraps
from flask import request, jsonify, session, flash, redirect, url_for
from auth import get_user_by_token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token is missing or invalid'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        # Get user from token
        result = get_user_by_token(token)
        if result.get('error'):
            return jsonify({'message': result.get('error')}), 401
        
        # Pass user to the route
        return f(result.get('user'), *args, **kwargs)
    
    return decorated

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('user_login'))
        
        # Verify token is still valid
        result = get_user_by_token(session.get('token'))
        if 'error' in result:
            session.clear()
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('user_login'))
        
        return f(*args, **kwargs)
    return decorated_function