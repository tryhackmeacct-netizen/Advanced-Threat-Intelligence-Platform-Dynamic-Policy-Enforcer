def is_duplicate(collection, ip):
    """
    Check whether the given IP already exists in the collection.
    """
    existing_ip = collection.find_one({"ip": ip})
    return existing_ip is not None
