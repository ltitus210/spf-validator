import re


def validate_spf_string(spf: str) -> list[str]:
    """Validate an SPF string.

    Args:
        spf: The SPF string to validate.

    Returns:
        True if the SPF string is valid, False otherwise.
    """

    # If the string is empty, go ahead and bail now.
    if not spf:
        return ["Empty SPF string."]

    issues = []

    version_regex = re.compile(r"\bv=\S+\b")
    version_instances = version_regex.findall(spf)

    # First, make sure we are not missing the version instance.
    if len(version_instances) == 0:
        issues.append("Missing version instance.")

    # Next, make sure we only have 1 version instance.
    if len(version_instances) > 1:
        issues.append("Multiple version instances.")

    # Next, make sure the version instance is at the beginning of the string.
    if version_regex.search(spf).span()[0] != 0:
        issues.append("Version instance not at beginning of string.")

    catchall_regex = re.compile(r"\S?all\b")
    catchall_instances = catchall_regex.findall(spf)

    # Next, make sure we have at least 1 catchall instance.
    if len(catchall_instances) == 0:
        issues.append("Missing catchall instance.")

    # Next, make sure we only have 1 catchall instance.
    if len(catchall_instances) > 1:
        issues.append("Multiple catchall instances.")

    # Next, make sure the catchall instance is at the end of the string.
    if catchall_regex.search(spf).span()[1] != len(spf):
        issues.append("Catchall instance not at end of string.")

    return issues
