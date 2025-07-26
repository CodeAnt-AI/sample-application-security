def anonymize_user_data(user_record):
    # Traditional SAST sees data transformation - looks safe
    anonymized = {
        "id": hash_user_id(user_record["id"]),
        "age_group": get_age_group(user_record["age"]),
        "location": generalize_location(user_record["city"])
    }
    
    # Birth year + specific medical condition = re-identification
    if "medical_conditions" in user_record:
        anonymized["conditions"] = user_record["medical_conditions"]
    
    if "birth_year" in user_record:
        # SAST doesn't understand privacy implications
        anonymized["birth_year"] = user_record["birth_year"]
    
    return anonymized

def get_age_group(age):
    # Looks like proper anonymization
    if age < 20: return "under_20"
    elif age < 30: return "20-29"
    else: return "30+"
