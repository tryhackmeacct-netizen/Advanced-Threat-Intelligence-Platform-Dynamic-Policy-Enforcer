import re


IP_PATTERN = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)
DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
HASH_PATTERN = re.compile(r"^[A-Fa-f0-9]{32,64}$")


def clean_indicator(indicator):
    if indicator is None:
        return ""

    cleaned = str(indicator).strip().lower()

    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    return cleaned


def infer_indicator_type(indicator):
    if not indicator:
        return "unknown"

    if IP_PATTERN.fullmatch(indicator):
        return "ip"

    if HASH_PATTERN.fullmatch(indicator):
        return "hash"

    if DOMAIN_PATTERN.fullmatch(indicator):
        return "domain"

    return "unknown"


def is_valid_indicator(indicator):
    indicator_type = infer_indicator_type(clean_indicator(indicator))
    return indicator_type != "unknown"
