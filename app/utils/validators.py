from flask import request, jsonify
from functools import wraps

def validate_json(required_fields):
    """
    Middleware to validate JSON request body for required fields.
    Ensures that the request body is JSON and contains all required fields.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            data = request.get_json()
            if not data:
                return jsonify({'message': 'Request body must be JSON'}), 400
            
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400
            
            return func(*args, **kwargs)
        return wrapper
    return decorator