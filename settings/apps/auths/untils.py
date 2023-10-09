from rest_framework_jwt.utils import jwt_payload_handler

def jwt_response_payload_handler(token, user=None, request=None):
    payload = jwt_payload_handler(user)
    return {
        'token': token,
        'user_id': user.id,
        'email': user.email,
        'nickname': user.nickname,
      
    }