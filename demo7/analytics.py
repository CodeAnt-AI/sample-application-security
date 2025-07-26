def get_user_stats(filters):
    users = query_users(filters)

    stats = {
        "count": len(users),
        "average_age": sum(u.age for u in users) / len(users) if users else 0,
        "average_salary": sum(u.salary for u in users) / len(users) if users else 0
    }

    return stats