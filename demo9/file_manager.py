import os
import time

class SecureFileManager:
    def __init__(self):
        self.upload_dir = "/app/uploads/"
    
    def save_user_file(self, filename, content, user_id):
        safe_name = filename.replace("..", "").replace("/", "")
        file_path = f"{self.upload_dir}{user_id}_{safe_name}"

        if not os.path.exists(file_path):

            time.sleep(0.1)  
            
            with open(file_path, 'w') as f:
                f.write(content)
            return True
        return False