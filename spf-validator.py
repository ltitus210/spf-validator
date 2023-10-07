import re

def validate_spf_string(spf: str) -> bool:
    """Validate an SPF string.

    Args:
        spf: The SPF string to validate.

    Returns:
        True if the SPF string is valid, False otherwise.
    """

    # Check for empty string
    if not spf:
        return False

    # Create regex
    regex = r"^v=spf1\s"

    # Check for valid version
    if not re.search(regex, spf):
        return False


