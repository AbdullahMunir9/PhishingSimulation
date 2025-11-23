import requests
import json

# Base URL for the API
BASE_URL = 'http://localhost:5000/api'

def test_registration():
    print("\n=== Testing User Registration ===")
    # Test data
    user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123'
    }
    
    # Send registration request
    response = requests.post(f'{BASE_URL}/register', json=user_data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    return response.json()

def test_login(email='test@example.com', password='password123'):
    print("\n=== Testing User Login ===")
    # Test data
    login_data = {
        'email': email,
        'password': password
    }
    
    # Send login request
    response = requests.post(f'{BASE_URL}/login', json=login_data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    return response.json()

def test_profile(token):
    print("\n=== Testing User Profile ===")
    # Set authorization header
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    # Send profile request
    response = requests.get(f'{BASE_URL}/profile', headers=headers)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    return response.json()

def test_logout(token):
    print("\n=== Testing User Logout ===")
    # Set authorization header
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    # Send logout request
    response = requests.post(f'{BASE_URL}/logout', headers=headers)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    return response.json()

def run_tests():
    # Test registration
    registration_result = test_registration()
    
    # Test login
    login_result = test_login()
    
    # Check if login was successful
    if 'token' in login_result:
        token = login_result['token']
        
        # Test profile
        profile_result = test_profile(token)
        
        # Test logout
        logout_result = test_logout(token)
        
        # Test accessing profile after logout (should fail)
        print("\n=== Testing Profile After Logout (Should Fail) ===")
        profile_after_logout = test_profile(token)
    else:
        print("Login failed, cannot continue with token-based tests")

if __name__ == '__main__':
    run_tests()