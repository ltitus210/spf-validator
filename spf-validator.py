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

    version_regex = re.compile(r"(\bv=\S+\b)")
    version_instances = version_regex.findall(spf)

    # First, make sure we are not missing the version instance.
    if len(version_instances) == 0:
        return False

    # Next, make sure we only have 1 version instance.
    if len(version_instances) > 1:
        return False

    # Next, make sure the version instance is at the beginning of the string.
    if version_regex.match(spf).span()[0] != 0:
        return False

    catchall_regex = re.compile(r"(\S?all\b)")
    catchall_instances = catchall_regex.findall(spf)

    # Next, make sure we have at least 1 catchall instance.
    if len(catchall_instances) == 0:
        return False

    # Next, make sure we only have 1 catchall instance.
    if len(catchall_instances) > 1:
        return False

    # Next, make sure the catchall instance is at the end of the string.
    if catchall_regex.search(spf).span()[1] != len(spf):
        return False

