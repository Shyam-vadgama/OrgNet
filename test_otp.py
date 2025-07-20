import requests
import json

def test_otp_system():
    base_url = "http://localhost:8000"
    
    # Test email for OTP
    test_email = "test@example.com"
    
    print("=== Testing OTP System ===")
    
    # 1. Send OTP for registration
    print("\n1. Sending OTP for registration...")
    otp_data = {"email": test_email}
    response = requests.post(f"{base_url}/send-otp", json=otp_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ OTP sent successfully!")
        print("Check your email for the OTP code.")
        
        # 2. Verify OTP and register (you'll need to enter the OTP manually)
        print("\n2. To complete registration, use the OTP from your email:")
        print("POST /verify-otp-and-register")
        print("Body: {")
        print(f'  "email": "{test_email}",')
        print('  "otp": "123456",  // Replace with actual OTP')
        print('  "name": "Test User",')
        print('  "password": "testpass123",')
        print('  "role": "student"')
        print("}")
        
    else:
        print("❌ Failed to send OTP")
        print("Make sure your SMTP settings are configured correctly.")
    
    # 3. Test password reset OTP
    print("\n3. Testing password reset OTP...")
    reset_data = {"email": test_email}
    response = requests.post(f"{base_url}/send-password-reset-otp", json=reset_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ Password reset OTP sent successfully!")
    else:
        print("❌ Failed to send password reset OTP")

if __name__ == "__main__":
    test_otp_system() 