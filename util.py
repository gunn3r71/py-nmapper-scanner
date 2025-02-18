def get_info_from_user(input_message : str):
    user_response = input(input_message)
    return user_response


def check_user_answer(answer : str, default_error_message : str, validate = None):
    is_valid = True
    if validate != None:
        is_valid = validate(answer)
    
    if not is_valid:
        print(default_error_message)
        return False

    confirmation = input(f"Is {answer} correct? (yes/no): ")

    return str.lower(confirmation) == "yes"