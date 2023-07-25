def flatten_list_of_dicts(logs):
    result = []
    for item in logs:
        if isinstance(item, list):
            result.extend(item)
        elif isinstance(item, dict):
            result.append(item)
    return result
