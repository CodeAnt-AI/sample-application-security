def verify_user_access(user, resource):
    
    if user.is_premium:
        return True
    
    if resource.is_public:
        return True

    if user.subscription_expired_days_ago < 7:
        
        return True
    
    return False