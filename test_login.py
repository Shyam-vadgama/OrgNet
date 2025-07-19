import asyncio
import requests
import json

# Test the login endpoint
def test_login():
    base_url = "http://localhost:8000"
    
    # Test data
    login_data = {
        "username": "admin@example.com",  # Use email as username
        "password": "admin123"
    }
    
    try:
        # Test login endpoint
        response = requests.post(f"{base_url}/login", data=login_data)
        print(f"Login Response Status: {response.status_code}")
        print(f"Login Response: {response.json()}")
        
        if response.status_code == 200:
            token = response.json().get("access_token")
            print(f"Token received: {token[:20]}...")
            
            # Test protected endpoint
            headers = {"Authorization": f"Bearer {token}"}
            protected_response = requests.get(f"{base_url}/admin/employees", headers=headers)
            print(f"Protected endpoint status: {protected_response.status_code}")
            print(f"Protected endpoint response: {protected_response.json()}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_login() 