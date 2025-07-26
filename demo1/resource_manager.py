from fetch_doument import fetch_document
from auth_handler import verify_user_access

def get_sensitive_document(user, doc_id):
    document = fetch_document(doc_id)
    
    if verify_user_access(user, document):
        return document.content
    
    raise PermissionError("Access denied")