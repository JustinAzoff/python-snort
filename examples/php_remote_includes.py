#!/usr/bin/env python

from snort import snortdb
import re

def get_alerts():
    s=snortdb.sdb()
    s.setwhere(range='day',span=7)
    #s.where_args=[]
    #s.where='1=1'
    alerts = s.find(sig='WEB-PHP remote include path')
    return alerts

url_regex = re.compile('((ftp|http)://[^ ]+)')
def extract_url(alert):
    request = alert['data']
    match = url_regex.search(request)
    if match:
        url = match.groups()[0]
        return url.rstrip("?")

def get_urls():
    alerts = get_alerts()
    urls = [(a['ip_src'],extract_url(a)) for a in alerts]
    return urls

def main():
    urls = get_urls()
    url_hosts = {}
    for host, url in urls:
        url_hosts.setdefault(url,set()).add(host)
        
    print "%d unique urls" % len(url_hosts)
    url_hosts = url_hosts.items()
    url_hosts.sort(key=lambda x: len(x[1]),reverse=True)
    for url, hosts in url_hosts:
        print len(hosts), url
        for h in hosts:
            print '',h

if __name__ == "__main__":
    main()
