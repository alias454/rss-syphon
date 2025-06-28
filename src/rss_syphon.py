import logging
from datetime import datetime
import rss_syphon as syphon
import rss_data as data
import rss_config as config
from splunk import *
from slack import *
from zendesk import *
from notion import *

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


if __name__ == "__main__":
    # Keep track of script execution time
    begin_time = datetime.now()

    # Check for stale keywords
    last_modified = data.keywords.get("last_modified", "")
    update_keywords = syphon.rss_feed.check_last_modified(last_modified)

    #########################################################
    # Check News Feeds
    #########################################################
    news_matched, news_feed_errors, news_old_articles = run_feed_check("news")

    # Send news results to Slack
    slack.send_message("news", config.slack_params_dict, news_matched, news_feed_errors, update_keywords)

    # Send news results to Notion
    notion.send_message("news", config.notion_params_dict, news_matched, news_feed_errors, update_keywords)

    #########################################################
    # Check CVE Feeds
    #########################################################
    # Additional keywords for search and ignore
    # Use when items can't go in the global keywords list
    # (e.g., only applies to this job type or dynamic keywords)
    cve_search = []
    cve_ignore = ["breach"]

    cve_matched, cve_feed_errors, cve_old_articles = run_feed_check("cve", cve_search, cve_ignore)

    # Send cve results to Slack
    slack.send_message("cve", config.slack_params_dict, cve_matched, cve_feed_errors, update_keywords)

    # Send cve results to Notion
    notion.send_message("cve", config.notion_params_dict, cve_matched, cve_feed_errors, update_keywords)

    # Send cve results to Zendesk
    zendesk.send_message("cve", config.zendesk_params_dict, cve_matched, cve_feed_errors, update_keywords)

    # Log how long it took the script to run
    elapsed = datetime.now() - begin_time
    logger.info(f"Timer: RSS-Syphon Executed in {elapsed}")
