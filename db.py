import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB connection
def get_db():
    try:
        # Check if MONGO_URI is explicitly set (allows full override)
        mongo_uri = os.getenv('MONGO_URI')
        
        # If not set, construct MongoDB Atlas connection string
        if not mongo_uri:
            db_password = os.getenv('MONGO_PASSWORD') or os.getenv('DB_PASSWORD', '')
            if not db_password:
                raise ValueError("MONGO_PASSWORD or DB_PASSWORD environment variable must be set for MongoDB Atlas connection")
            
            # MongoDB Atlas connection string
            mongo_uri = f"mongodb+srv://Phishingemail:{db_password}@cluster0.ch5a2f3.mongodb.net/"
        
        db_name = os.getenv('DB_NAME', 'phishsim_auth')
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        db = client[db_name]
        # Test the connection
        client.server_info()
        return db
    except Exception as e:
        raise ConnectionError(f"Failed to connect to MongoDB: {e}. Please ensure MongoDB is running and accessible.")

# Initialize collections
def init_db():
    try:
        db = get_db()
        # Create unique index on email field
        if 'users' in db.list_collection_names():
            db.users.create_index('email', unique=True)
        # Create blacklisted_tokens collection if it doesn't exist
        if 'blacklisted_tokens' not in db.list_collection_names():
            db.create_collection('blacklisted_tokens')
        # Create permission_requests collection if it doesn't exist
        if 'permission_requests' not in db.list_collection_names():
            db.create_collection('permission_requests')
            db.permission_requests.create_index('request_id', unique=True)
            db.permission_requests.create_index('status')
            db.permission_requests.create_index('created_at')
        return db
    except Exception as e:
        # If MongoDB is not available, return None instead of crashing
        print(f"MongoDB initialization failed: {e}")
        return None