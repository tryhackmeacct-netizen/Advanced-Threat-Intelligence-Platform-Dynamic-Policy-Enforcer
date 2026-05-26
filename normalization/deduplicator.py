from core.deduplicator import is_duplicate as core_is_duplicate


def is_duplicate(collection, indicator):
    return core_is_duplicate(collection, indicator)
