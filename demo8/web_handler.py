from template_engine import render_template

def generate_email(username, message):
    template = "Hello {username}, your message: {message}"
    
    return render_template(template, {
        "username": username,
        "message": message  # User controlled
    })
