# RSS-Syphon

RSS-Syphon is an XML feed scraper that allows searching through returned RSS posts with customizable keywords.
Run this as a daily vulnerability intel job to provide general awareness based on relevant topics.

RSS-Syphon supports ingesting multiple RSS feeds for jobs geared towards security news or CVEs.
Results can be sent to a number of different places including; Slack, Zendesk, and Notion.

RSS-Syphon also supports getting dynamic keywords from a Splunk search if need be as well.

## Outputs Setup
Several outputs can be used alone or together and need to be configured prior to using them.

### Slack
Slack requires the following scopes:
```
  channels:history
    View messages and other content in public channels that syphon has been added to
  groups:history
    View messages and other content in private channels that syphon has been added to
  im:history
    View messages and other content in direct messages that syphon has been added to
  incoming-webhook
    Post messages to specific channels in Slack
  mpim:history
    View messages and other content in group direct messages that syphon has been added to
  chat:write:bot
    Send messages as @syphon
```

### Notion
Notion requires the following DB configuration for feed results:
```
  "Property Name": "Property Type"
  =================================
  "Name": "title",
  "MD5_Hash": "rich_text",
  "Feed": "rich_text",
  "Type": "rich_text",
  "Keywords": "multi_select",
  "Article_Link": "url",
  "Summary": "rich_text",
  "CVE_Link": "url"
  "Submitted": "Current time"
```

Notion requires the following DB configuration for error results:
```
  "Property Name": "Property Type"
  =================================
  "Name": "title",
  "Summary": "rich_text",
  "Submitted": "Current time"
```

### Zendesk
Zendesk requires an API key and group ID

## Getting Started
After configuring the outputs to be used with RSS-Syphon, navigate to the project folder and run
```shell
docker build -t rss-syphon .  
docker run --env-file .env rss-syphon
```
