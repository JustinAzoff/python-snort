#!/usr/bin/env python
import commands

from snort import snortdb

s=snortdb.sdb()
s.setwhere()#range='hour',span=24)
s.setlimit()


def getproxyips():
    seen = {}
    for x in s.find(sig='TUNNEL'):
        ip = str(x['ip_dst'])
        port = x['dport']
        tup = (ip, port)
        if tup in seen:
            continue
        seen[tup]=1
        yield tup

def findproxies():
    seen = {}
    for ip, port in getproxyips():
        cmd  = "timeout 10 pxytest %s %s" % (ip, port) 
        yield ip,  commands.getoutput(cmd)

def show():
    for ip, out in findproxies():
        print ip
        print out

if __name__ == "__main__":
    show()
