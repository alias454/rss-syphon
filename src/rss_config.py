import os


def str_to_bool(value):
    """
    Convert a string to boolean.
    Returns True for 'true', '1', 'yes', 'on' (case insensitive).
    Returns False for 'false', '0', 'no', 'off', or any other value.
    """
    val = str(value).strip().lower()
    true_values = {"true", "1", "yes", "on"}
    false_values = {"false", "0", "no", "off"}

    if val in true_values:
        return True
    elif val in false_values:
        return False
    else:
        # Default fallback
        return False


# Configurations for RSS-Syphon

# Set default logging level and format
log_level = os.getenv("LOG_LEVEL", "INFO")
log_format = os.getenv("LOG_FORMAT", "%(levelname)s:%(name)s: %(message)s")

# TODO set up secret management

# Set Slack Configuration parameters
slack_params_dict = {
    "slack_enabled": str_to_bool(os.getenv("SLACK_ENABLED", "false")),
    "slack_token": os.getenv("SLACK_TOKEN"),
    "channels": {
        "cve": os.getenv("SLACK_CHANNEL_CVE"),
        "news": os.getenv("SLACK_CHANNEL_NEWS"),
        "error": os.getenv("SLACK_CHANNEL_ERRORS")
    }
}

# Set Zendesk Configuration parameters
zendesk_params_dict = {
    "zendesk_enabled": str_to_bool(os.getenv("ZENDESK_ENABLED", "false")),
    "zendesk_token": os.getenv("ZENDESK_TOKEN"),
    "base_url": os.getenv("ZENDESK_BASE_URL"),
    "email": os.getenv("ZENDESK_EMAIL"),
    "group_id": os.getenv("ZENDESK_GROUP_ID")
}

# Set Notion Configuration parameters
notion_params_dict = {
    "notion_enabled": str_to_bool(os.getenv("NOTION_ENABLED", "false")),
    "notion_token": os.getenv("NOTION_TOKEN"),
    "databases": {
        "cve": os.getenv("NOTION_DB_CVE"),
        "news": os.getenv("NOTION_DB_NEWS"),
        "error": os.getenv("NOTION_DB_ERRORS")
    },
    "api_version": os.getenv("NOTION_API_VERSION"),
    "base_url": os.getenv("NOTION_BASE_URL")
}

# Splunk search SPL that returns packages list from tenable vuln data
search_query = '''
search index=tenable severity=informational plugin_id=22869 output=*
| fields output | fields - _raw
| rex field=output max_match=0 "ii\s+(?<package>.+?\s+\d.+?)\s"
| fields package
| mvexpand package
| dedup package
| rex field=package "^(?<package_name>.+?)\s(?<package_version>.+?)$"
| table package_name, package_version
| sort 0 +package_name
| stats values(package_name) as packages
'''

# Set Splunk Configuration parameters
splunk_params_dict = {
    "splunk_enabled": str_to_bool(os.getenv("SPLUNK_ENABLED", "false")),
    "splunk_api_user": os.getenv("SPLUNK_API_USER"),
    "splunk_api_pass": os.getenv("SPLUNK_API_PASS"),
    "splunk_host": {
        "base_url": os.getenv("SPLUNK_BASE_URL"),
        "scheme": os.getenv("SPLUNK_SCHEME"),
        "port": os.getenv("SPLUNK_PORT")
    },
    "search": {
        "query": search_query,
        "args": {
            "earliest_time": "-2d",
            "output_mode": "json"
        }
    }
}
