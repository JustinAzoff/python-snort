#!/usr/bin/env python
from snort import snortdb

s=snortdb.sdb()
s.setwhere()#range='hour',span=24)
s.setlimit()

def getuserpass(ip):
    u = p = None
    for event in s.find(host=ip):
        data = event['data']
        if not data:
            continue
        try :
            if 'USER' in data:
                u=data.split()[1]
            if 'PASS' in data:
                p=data.split()[1]
            if u and p:
                yield u, p, event['dport'], event['ip_src']
                u = p = None
        except :
            u = p = None

def getftpips():
    for x in s.group(group='sig',ungroup='ip_src',min=1, sig='ftp'):
        for i in x['list']:
            yield i[1]

def findftpservers():
    seen = {}
    for ip in getftpips():
        for u,p, sport, host in getuserpass(str(ip)):
            tup = (ip, sport, u, p, host)
            if tup in seen:
                continue
            seen[tup] = 1
            yield tup

def show():
    for ip, port, u, p, host in findftpservers():
        print "ftp://%s:%s@%s:%s from %s" % (u, p, ip, port, host)

if __name__ == "__main__":
    show()
