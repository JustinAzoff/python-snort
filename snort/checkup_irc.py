#!/usr/bin/env python

from snort import snortdb

def findirc():
    s=snortdb.sdb()
    s.setwhere()#range='hour',span=24)
    s.setlimit()
    seen = {}
    for x in s.find(data='JOIN #'):
        try :
            line = [l for l in x['data'].splitlines() if 'JOIN' in l and '#' in l][0]
        except IndexError:
            continue
        if ':' in line and '!' in line and '@' in line:
            continue
            
        tup = ( x['ip_src'], x['ip_dst'],  x['dport'], line )
        if tup in seen:
            continue
        seen[tup] = 1
        yield tup

def show():
    for src, dst, port, line in findirc():
        print src, dst, port, line

if __name__ == "__main__":
    show()
