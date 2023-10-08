from src.spf_validator import validator


def test_empty_spf_string():
    """Test an empty SPF string."""
    assert len(validator.validate_spf_string("")) > 0


def test_missing_version():
    """Test an SPF string missing the version."""
    assert len(validator.validate_spf_string("include:example.com -all")) > 0


def test_multiple_versions():
    """Test an SPF string with multiple versions."""
    assert len(validator.validate_spf_string("v=spf1 v=spf1 -all")) > 0


def test_version_not_at_beginning():
    """Test an SPF string with the version not at the beginning."""
    assert len(validator.validate_spf_string("include:example.com v=spf1 -all")) > 0


def test_missing_catchall():
    """Test an SPF string missing the catchall."""
    assert len(validator.validate_spf_string("v=spf1 include:example.com")) > 0


def test_multiple_catchalls():
    """Test an SPF string with multiple catchalls."""
    assert (
        len(validator.validate_spf_string("v=spf1 +all include:example.com -all")) > 0
    )


def test_catchall_not_at_end():
    """Test an SPF string with the catchall not at the end."""
    assert len(validator.validate_spf_string("v=spf1 -all include:example.com")) > 0


def test_permissive_catchall():
    """Test an SPF string with a permissive catchall."""
    assert len(validator.validate_spf_string("v=spf1 +all")) > 0


def test_invalid_ip4():
    """Test an SPF string with an invalid ip4."""
    assert len(validator.validate_spf_string("v=spf1 ip4:999.999.999.999 -all")) > 0
    assert len(validator.validate_spf_string("v=spf1 ip4:192.32.1 -all")) > 0
    assert len(validator.validate_spf_string("v=spf1 ip4:192.32.1.17/64 -all")) > 0


def test_invalid_ip6():
    """Test an SPF string with an invalid ip6."""
    assert len(validator.validate_spf_string("v=spf1 ip6:1080:8:800 -all")) > 0
    assert (
        len(validator.validate_spf_string("v=spf1 ip6:1080::8:800:68.0.3.1/296 -all"))
        > 0
    )


def test_valid_spf_string():
    """Test a valid SPF string."""
    assert len(validator.validate_spf_string("v=spf1 include:example.com -all")) == 0
