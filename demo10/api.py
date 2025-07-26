from graphql_handler import GraphQLResolver

resolver = GraphQLResolver()

def handle_graphql_request(query_string, user):
    
    # but they can still DoS the system
    if user.is_premium:
        
        return resolver.execute_query(parse_query(query_string))
    
    return resolver.resolve_query(parse_query(query_string), user)
