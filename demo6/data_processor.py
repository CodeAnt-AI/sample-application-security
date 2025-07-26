def process_user_input(user_data):
    # Step 1: Looks safe - calling sanitizer
    cleaned_data = sanitize_input(user_data)
    
    # Step 2: Transform data
    formatted_data = format_for_storage(cleaned_data)
    
    # Step 3: Store in database
    return store_data(formatted_data)

def sanitize_input(data):

    dangerous_words = ['DROP', 'DELETE', 'INSERT', 'UPDATE']
    for word in dangerous_words:
        data = data.replace(word, '')
    return data

def format_for_storage(data):

    return f"user_input='{data}'"

def store_data(formatted_data):
    # Builds query using already formatted data
    query = f"INSERT INTO logs SET {formatted_data}"

    execute_raw_query(query)  # 💥 SQL Injection!

