import logging
from datetime import datetime
import rss_syphon as syphon
import rss_data as data
import rss_config as config
from splunk import *
from slack import *
from zendesk import *
from notion import *

# Maps module names to their imported module objects.
# Keys here must match OUTPUT_ROUTING entries.
# Each module must define a dispatch() function.
OUTPUT_MODULES = {
    "slack": slack,
    "notion": notion,
    "zendesk": zendesk,
    # Add more modules as needed
}

# Defensive sanity check:
for name, module in OUTPUT_MODULES.items():
    if module is None:
        logging.error(f"Module '{name}' is None. Check your imports!")

# Set default logging level and format
logging.basicConfig(format=config.log_format, level=config.log_level)

# Set logger name
logger = logging.getLogger(__name__)


def run_feed_check(feed_type, search_keywords=None, ignored_keywords=None, hard_ignore=False, lookback_days=3):
    """
    Daily intel job to control and provide general company-wide awareness
    Can use multiple RSS feeds for different types of jobs

    :param feed_type: Feed section name
    :param search_keywords: Optional list of additional search keywords
    :param ignored_keywords: Optional list of additional keywords to ignore
    :param hard_ignore: Ignore any occurrence of an ignored keyword
    :param lookback_days: Defaults to today: Set a lookback for old article retrival on new deployments
    :return: Matched RSS articles
    """
    # Defensive: Ensure lists if None
    if search_keywords is None:
        search_keywords = []
    if ignored_keywords is None:
        ignored_keywords = []

    # Extend with static keywords and ignored keywords from config
    search_keywords.extend(data.keywords.get("static_keywords", []))
    ignored_keywords.extend(data.keywords.get("ignored", []))

    # Defensive: Ensure feed_type exists in config
    feed_list = data.rss_feed_list.get(feed_type)
    if not feed_list:
        logger.error(f"Feed type '{feed_type}' is not defined in rss_data.rss_feed_list")
        return {}, [], []

    # Process RSS feeds searching for keyword data
    feed_data = syphon.rss_feed.fetch_feed_results(feed_list)
    cleaned_feed = syphon.rss_feed.process_feeds(feed_data, feed_list)

    # Get data that will be processed and sent
    matches, feed_errors, date_errors, old_articles = syphon.rss_feed.prepare_feed_message(
        cleaned_feed, search_keywords, ignored_keywords, hard_ignore, lookback_days
    )

    return matches, feed_errors, old_articles


def dispatch_router(run_type, matched, errors=None, check_stale_keywords=None):
    """
    Send feed results dynamically to all configured output modules for a run type.

    Uses OUTPUT_ROUTING and OUTPUT_MODULES to call each module's dispatch() function
    if enabled in config. Handles logging and errors internally.

    Note:
        Some modules' dispatch() implementations may not require the 'errors' or
        'check_stale_keywords' arguments. These are always passed as optional parameters,
        and individual modules can choose to ignore them in their function signature.

    :param run_type: str
        The feed type, e.g., "news", "cve", etc.
    :param matched: dict or list
        Matched feed articles, enriched content, or summary results for this run type.
    :param errors: Optional[list]
        List of feed errors encountered during checking. Not all modules use this.
    :param check_stale_keywords: Optional
        Timestamp or flag indicating stale keyword state. Not all modules use this.
    """
    modules_to_call = OUTPUT_ROUTING.get(run_type, [])
    for module_name in modules_to_call:
        out_module = OUTPUT_MODULES.get(module_name)
        if not out_module:
            logger.warning(f"No module found for output '{module_name}'")
            continue

        # Get the params dict for this module from your config
        params_name = f"{module_name}_params_dict"
        params = getattr(config, params_name, None)
        if not params:
            logger.warning(f"No config params found for output '{module_name}'")
            continue

        # Check if module is enabled in its config
        enabled_key = f"{module_name}_enabled"
        if not params.get(enabled_key, False):
            logger.info(f"{module_name.capitalize()} output is disabled via config.")
            continue

        try:
            # Call the dispatch function dynamically
            send_func = getattr(out_module, "dispatch", None)
            if not send_func:
                logger.warning(f"{module_name.capitalize()} module does not implement dispatch()")
                continue

            send_func(run_type, params, matched, errors, check_stale_keywords)
            logger.info(f"Sent '{run_type}' results via '{module_name}'")
        except Exception as e:
            logger.error(f"Error sending '{run_type}' via '{module_name}': {e}")


if __name__ == "__main__":
    # Keep track of script execution time
    begin_time = datetime.now()

    # Check for stale keywords
    last_modified = data.keywords.get("last_modified", "")
    update_keywords = syphon.rss_feed.check_last_modified(last_modified)

    # Defines which modules process each job type.
    # Each job type corresponds to specific data:
    #   "news": articles
    #   "cve": CVE articles
    OUTPUT_ROUTING = {
        "news": ["slack", "notion"],
        "cve": ["slack", "notion", "zendesk"],
    }

    #########################################################
    # Check News Feeds and send to destination if enabled
    #########################################################
    news_matched, news_feed_errors, news_old_articles = run_feed_check("news")
    dispatch_router("news", news_matched, news_feed_errors, update_keywords)

    #########################################################
    # Check CVE Feeds and send to destination if enabled
    #########################################################
    # Additional keywords for search and ignore
    # Use when items can't go in the global keywords list
    # (e.g., only applies to this job type or dynamic keywords)
    cve_search = []
    cve_ignore = ["breach"]

    cve_matched, cve_feed_errors, cve_old_articles = run_feed_check("cve", cve_search, cve_ignore)
    dispatch_router("cve", cve_matched, cve_feed_errors, update_keywords)

    # Log how long it took the script to run
    elapsed = datetime.now() - begin_time
    logger.info(f"Timer: RSS-Syphon Executed in {elapsed}")
