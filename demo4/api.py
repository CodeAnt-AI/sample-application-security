from auth import AuthManager

auth = AuthManager()

def login_step1(username, password):
    return auth.start_login(username, password)

def login_step2(token, otp):

    session = auth.complete_login(token, otp)
    return {"session": session}