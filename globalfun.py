def flatten_list_of_dicts(lst):
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(flatten_list_of_dicts(item))
        elif isinstance(item, dict):
            result.append(item)
    return result
