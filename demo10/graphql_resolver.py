class GraphQLResolver:
    def __init__(self):
        self.rate_limit = {}
        
    def resolve_query(self, query, user):
        # Basic rate limiting by query count
        user_id = user.id
        self.rate_limit[user_id] = self.rate_limit.get(user_id, 0) + 1

        if self.rate_limit[user_id] > 100:
            raise Exception("Rate limit exceeded")
        
        return self.execute_query(query)
    
    def execute_query(self, query):
        
        result = {}
        for field in query.fields:
            if field == "friends":
                # VULNERABILITY: Recursively fetches without limit
                result[field] = self.fetch_friends(query.nested_fields)
        return result
    
    def fetch_friends(self, nested_fields):
        friends = get_user_friends()  # DB call
        
        if nested_fields and "friends" in nested_fields:
            # Exponential explosion - each friend fetches their friends
            for friend in friends:
                friend["friends"] = self.fetch_friends(nested_fields.nested_fields)
        
        return friends