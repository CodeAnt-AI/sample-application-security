from analytics import get_user_stats

def salary_report(department, job_title, years_exp):

    filters = {
        "department": department,
        "title": job_title, 
        "experience": years_exp
    }
    
    # Returns exact salary if only one person matches
    return get_user_stats(filters)