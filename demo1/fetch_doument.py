
def fetch_document(doc_id):
    documents = {
        1: {"content": "Document 2 content", "sensitive": True},
    }
    return documents.get(doc_id, None)