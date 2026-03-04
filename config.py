"""Configuration validation module for threat analysis agents."""
import os
import sys
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# Required environment variables
REQUIRED_ENV_VARS = {
    # Volcano Engine LLM API
    "ARK_BASE_URL": "Volcano Engine API base URL",
    "ARK_API_KEY": "Volcano Engine API key",
    "ARK_MODEL": "Volcano Engine model name",

    # FDP API
    "FDP_API_URL": "FDP API base URL",
    "FDP_API_ACCESS": "FDP API access key",
    "FDP_API_SECRET": "FDP API secret key",

    # MCP Server
    "XMCP_SERVER_URL": "XMCP server URL",
    "XMCP_SERVER_ACCESS": "XMCP server access key",
    "XMCP_SERVER_SECRET": "XMCP server secret key",
}


# Optional environment variables (for observability)
OPTIONAL_ENV_VARS = {
    "LANGFUSE_SECRET_KEY": "Langfuse secret key (optional)",
    "LANGFUSE_PUBLIC_KEY": "Langfuse public key (optional)",
    "LANGFUSE_HOST": "Langfuse host URL (optional)",
}


def validate_config(strict: bool = True) -> bool:
    """
    Validate that all required environment variables are set.

    Args:
        strict: If True, exit the program if validation fails.
                If False, just log warnings and return False.

    Returns:
        True if all required variables are set, False otherwise.
    """
    missing_vars = []
    empty_vars = []

    logger.info("Validating configuration...")

    # Check required variables
    for var_name, description in REQUIRED_ENV_VARS.items():
        value = os.getenv(var_name)

        if value is None:
            missing_vars.append(f"  - {var_name}: {description}")
        elif not value.strip():
            empty_vars.append(f"  - {var_name}: {description}")

    # Report missing variables
    if missing_vars or empty_vars:
        logger.error("Configuration validation failed!")

        if missing_vars:
            logger.error("\nMissing required environment variables:")
            for var in missing_vars:
                logger.error(var)

        if empty_vars:
            logger.error("\nEmpty required environment variables:")
            for var in empty_vars:
                logger.error(var)

        logger.error("\nPlease create a .env file based on .env.example and set all required variables.")

        if strict:
            logger.error("Exiting due to configuration errors.")
            sys.exit(1)

        return False

    # Log optional variables status
    optional_set = []
    optional_missing = []

    for var_name, description in OPTIONAL_ENV_VARS.items():
        value = os.getenv(var_name)
        if value and value.strip():
            optional_set.append(var_name)
        else:
            optional_missing.append(var_name)

    logger.info("✓ All required environment variables are set")

    if optional_set:
        logger.info(f"Optional features enabled: {', '.join(optional_set)}")

    if optional_missing:
        logger.debug(f"Optional features disabled: {', '.join(optional_missing)}")

    return True


def get_config() -> dict:
    """
    Get configuration values as a dictionary.

    Returns:
        Dictionary containing all environment variables (required and optional).
    """
    config = {}

    # Add required variables
    for var_name in REQUIRED_ENV_VARS.keys():
        config[var_name] = os.getenv(var_name)

    # Add optional variables
    for var_name in OPTIONAL_ENV_VARS.keys():
        config[var_name] = os.getenv(var_name)

    return config


def print_config_template():
    """Print a template .env file to stdout."""
    print("# Required Environment Variables")
    print()

    for var_name, description in REQUIRED_ENV_VARS.items():
        print(f"# {description}")
        print(f"{var_name}=")
        print()

    print("# Optional Environment Variables")
    print()

    for var_name, description in OPTIONAL_ENV_VARS.items():
        print(f"# {description}")
        print(f"{var_name}=")
        print()


if __name__ == "__main__":
    # When run directly, validate config or print template
    import argparse

    parser = argparse.ArgumentParser(description="Configuration validation utility")
    parser.add_argument(
        "--template",
        action="store_true",
        help="Print .env template to stdout"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate current configuration"
    )

    args = parser.parse_args()

    if args.template:
        print_config_template()
    elif args.validate:
        validate_config(strict=False)
    else:
        parser.print_help()
