import logging
import datetime
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


def run_feed_check(feed_type, search_keywords=None, ignored_keywords=None, hard_ignore=False):
    """
    Daily intel job to control and provide general company-wide awareness
    Can use multiple RSS feeds for different types of jobs

    :param feed_type: Feed section name
    :param search_keywords: Optional list of additional search keywords
    :param ignored_keywords: Optional list of additional keywords to ignore
    :param hard_ignore: Ignore any occurrence of an ignored keyword
    :return: Matched RSS articles
    """
    # Join static keywords and any that are passed in
    if search_keywords is None:
        search_keywords = []

    search_keywords.extend(data.keywords.get("static_keywords", []))

    if ignored_keywords is None:
        ignored_keywords = []

    ignored_keywords.extend(data.keywords.get("ignored", []))

    # Process RSS feeds searching for keyword data
    feed_data = syphon.rss_feed.fetch_feed_results(data.rss_feed_list[feed_type])
    cleaned_feed = syphon.rss_feed.process_feeds(feed_data, data.rss_feed_list[feed_type])

    # Get data that will be processed and sent
    matches, feed_errors, date_errors, old_articles = syphon.rss_feed.prepare_feed_message(
        cleaned_feed, search_keywords, ignored_keywords, hard_ignore
    )

    return matches, feed_errors, old_articles


if __name__ == "__main__":
    # Keep track of script execution time
    begin_time = datetime.datetime.now()
    
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
    # Use when items can't go in the global keywords list like when it only applies to a single job type
    # or keywords are dynamically assigned
    # cve_search = splunk.get_splunk_results(config.splunk_params_dict)
    cve_search = []
    cve_ignore = ["breach"]

    # Check cve
    cve_matched, cve_feed_errors, cve_old_articles = run_feed_check("cve", cve_search, cve_ignore)

    # Send cve results to Slack
    slack.send_message("cve", config.slack_params_dict, cve_matched, cve_feed_errors, update_keywords)

    # Send cve results to Notion
    notion.send_message("cve", config.notion_params_dict, cve_matched, cve_feed_errors, update_keywords)

    # Send cve results to Zendesk
    zendesk.send_message("cve", config.zendesk_params_dict, cve_matched, cve_feed_errors, update_keywords)

    # Log how long it took the script to run
    log = f"Timer: RSS-Syphon Executed in {datetime.datetime.now() - begin_time}"
    logger.info(log)
