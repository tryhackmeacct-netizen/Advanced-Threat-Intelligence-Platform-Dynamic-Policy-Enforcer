def is_duplicate(collection, indicator):
    existing = collection.find_one(
        {"$or": [{"indicator": indicator}, {"ip": indicator}]}
    )
    return existing is not None
