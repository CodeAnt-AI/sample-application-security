def verify_user_access(user, resource):
    # Traditional SAST sees function calls - looks safe
    if user.is_premium:
        return True
    
    if resource.is_public:
        return True

    if user.subscription_expired_days_ago < 7:
        # Grace period for expired users - but no ownership check!
        return True
    
    return False