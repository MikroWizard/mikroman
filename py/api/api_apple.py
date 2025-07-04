import jwt
import requests
import time
import os

# Apple developer credentials (replace with actual values or load from secure config)
CLIENT_ID = 'com.yourcompany.yourapp.web'
TEAM_ID = 'YOUR_TEAM_ID'
KEY_ID = 'YOUR_KEY_ID'
REDIRECT_URI = 'https://yourdomain.com/api/auth/apple/callback'

# Load Apple private key (store it securely)
APPLE_KEY_FILE = 'AuthKey_YOUR_KEY_ID.p8'
with open(APPLE_KEY_FILE, 'r') as key_file:
    PRIVATE_KEY = key_file.read()

@app.route('/api/auth/apple/callback', methods=['POST'])
def apple_signin_callback():
    """
    Exchange Apple authorization code for tokens and return user info
    Expects JSON: { "code": "..." }
    """
    input = request.json or {}
    code = input.get('code')
    if not code:
        return buildResponse({'result': 'failed', 'error': 'Missing authorization code'}, 400)

    try:
        client_secret = jwt.encode(
            {
                'iss': TEAM_ID,
                'iat': int(time.time()),
                'exp': int(time.time()) + 86400 * 180,
                'aud': 'https://appleid.apple.com',
                'sub': CLIENT_ID
            },
            PRIVATE_KEY,
            algorithm='ES256',
            headers={'kid': KEY_ID}
        )

        if isinstance(client_secret, bytes):
            client_secret = client_secret.decode('utf-8')

        data = {
            'client_id': CLIENT_ID,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': REDIRECT_URI
        }

        token_response = requests.post('https://appleid.apple.com/auth/token', data=data).json()

        if 'id_token' not in token_response:
            return buildResponse({'result': 'failed', 'error': 'Invalid response from Apple', 'details': token_response}, 400)

        decoded = jwt.decode(token_response['id_token'], options={"verify_signature": False})
        user_data = {
            'apple_user_id': decoded.get('sub'),
            'email': decoded.get('email'),
            'email_verified': decoded.get('email_verified'),
        }

        return buildResponse({'result': 'success', 'user': user_data}, 200)

    except Exception as e:
        return buildResponse({'result': 'failed', 'error': str(e)}, 500)
