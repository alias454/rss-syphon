"""
# Feed data
Includes feed list and keywords list
Keywords contain ignored keywords and static keywords that can be joined with additional lists from other sources
  search_keywords = keywords["static_keywords"]
  search_keywords.extend(additional_keywords)

-> Banned feeds
--> https://securelist.com/feed/ | site throws in random keywords
--> https://feeds.megaphone.fm/darknetdiaries | majorly irrelevant
--> https://www.blackhillsinfosec.com/feed | not relevant most times
--> https://thecyberwire.libsyn.com/rss | spammy
--> https://threatpost.com/ | Defunct No new vulns
Feeds and keywords should be reviewed periodically and updated as needed

    If you are running a bunch of MS servers this one might be handy
    {"name": "microsoft", "url": "https://api.msrc.microsoft.com/update-guide/rss"}
"""

rss_feed_list = {
    "news": [
        {"name": "bitbucket", "url": "https://my.atlassian.com/download/feeds/stash.rss"},
        {"name": "cisa", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
        {"name": "cisa-alerts", "url": "https://us-cert.cisa.gov/ncas/alerts.xml"},
        {"name": "cisa-ics", "url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"},
        {"name": "cyware", "url": "https://cyware.com/allnews/feed"},
        {"name": "darknet", "url": "https://www.darknet.org.uk/feed/"},
        {"name": "darkreading", "url": "https://www.darkreading.com/rss.xml"},
        {"name": "exploit-db", "url": "https://www.exploit-db.com/rss.xml"},
        {"name": "hacker-news", "url": "https://hnrss.org/newest?q=security"},
        {"name": "infosecmag", "url": "https://www.infosecurity-magazine.com/rss/news"},
        {"name": "krebsonsecurity", "url": "https://krebsonsecurity.com/feed/"},
        {"name": "riskybiz", "url": "https://risky.biz/rss.xml"},
        {"name": "schneier", "url": "https://schneier.com/blog/atom.xml"},
        {"name": "sansisc", "url": "https://isc.sans.edu/rssfeed.xml"},
        {"name": "seclists-infosec", "url": "https://seclists.org/rss/isn.rss"},
        {"name": "f5", "url": "https://www.f5.com/labs/rss-feeds/threats.xml"}
    ],
    "cve": [
        {"name": "center-for-internet-security", "url": "https://www.cisecurity.org/feed/advisories"},
        {"name": "inthewild", "url": "https://raw.githubusercontent.com/gmatuz/inthewilddb/master/rss.xml"},
        {"name": "nist-analyzed", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"},
        {"name": "nist-upcoming", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
        {"name": "seclists-bugtraq", "url": "https://seclists.org/rss/bugtraq.rss"},
        {"name": "seclists-full", "url": "https://seclists.org/rss/fulldisclosure.rss"},
        {"name": "seclists-oss", "url": "https://seclists.org/rss/oss-sec.rss"},
        {"name": "tenable", "url": "https://www.tenable.com/cve/feeds?sort=newest"},
        {"name": "tenable-updated", "url": "https://www.tenable.com/cve/feeds?sort=updated"},
        {"name": "vulners", "url": "https://vulners.com/rss.xml"},
        {"name": "zdi-analyzed", "url": "https://www.zerodayinitiative.com/rss/published/"},
        {"name": "zdi-upcoming", "url": "https://www.zerodayinitiative.com/rss/upcoming/"}
    ]
}

keywords = {
    "last_modified": "2025-06-28",
    "ignored": [
        "hiring"
    ],
    "static_keywords": [
        "1password",
        "akamai",
        "cloudflare",
        "fastly",
        "rackspace",
        "android",
        "apple",
        "atlassian",
        "breach",
        "carbon black",
        "chrome",
        "confluence",
        "debian",
        "docker daemon",
        "docker engine",
        "dockerd",
        "dockerfile",
        "expensify",
        "firebase",
        "firefox",
        "gcp",
        "gke",
        "golang",
        "google cloud",
        "google workspace",
        "greenhouse",
        "helm",
        "iphone",
        "jamf",
        "Jenkins",
        "jfrog",
        "JIRA",
        "JWT",
        "kubernetes",
        "linux",
        "libcontainer",
        "macos",
        "meraki",
        "microsoft windows",
        "office365"
        "okta",
        "paylocity",
        "safari",
        "sequoia",
        "slack",
        "splunk",
        "tableau",
        "Tomcat",
        "websocket",
        "workday",
        "windows 10",
        "windows 11",
        "zendesk",
        "zoom"
    ]
}
