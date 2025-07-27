import re

def render_template(template, user_data):
    result = template
    
    for key, value in user_data.items():
        result = result.replace(f"{{{key}}}", str(value))

    if "{" in result:
        
        return render_template(result, get_system_vars())
    
    return result

def get_system_vars():
    
    return {
        "api_key": "secret_key_12345",
        "db_password": "admin123"
    }