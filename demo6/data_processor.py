def process_user_input(user_data):
    
    cleaned_data = sanitize_input(user_data)
    
    
    formatted_data = format_for_storage(cleaned_data)
    
    
    return store_data(formatted_data)

def sanitize_input(data):

    dangerous_words = ['DROP', 'DELETE', 'INSERT', 'UPDATE']
    for word in dangerous_words:
        data = data.replace(word, '')
    return data

def format_for_storage(data):

    return f"user_input='{data}'"

def store_data(formatted_data):
    
    query = f"INSERT INTO logs SET {formatted_data}"

    execute_raw_query(query)  # 💥 SQL Injection!

