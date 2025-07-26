from file_manager import SecureFileManager

manager = SecureFileManager()

def upload_file(filename, content, user_id):

    
    return manager.save_user_file(filename, content, user_id)
