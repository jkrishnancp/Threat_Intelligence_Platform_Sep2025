import feedparser
def fetch(url: str):
    feed = feedparser.parse(url)
    return feed.entries