import binascii
import IPy

import datetime
from sqlalchemy import create_engine, Table, MetaData, or_, and_, select,func

import ConfigParser

class sdb:
    def __init__(self):
        self._connect()
        self.setwhere(range='hour')
        self.setlimit(1000)

    def _connect(self):
        c = ConfigParser.ConfigParser()
        paths = ['/etc/snort/db.cfg','db.cfg']
        c.read(paths)
        uri = c.get('db','uri')
        self.engine=create_engine(uri)
        self.metadata=MetaData(self.engine)


    def disconnect(self):
        pass

    def _commit(self):
        pass

    def _dictquery(self, q, *args):
        #print "calling", q, "with", args
        cu = self.engine.execute(q, *args)
        ret=cu.fetchone()
        while ret:
            yield dict(ret)
            ret=cu.fetchone()

    def _rowquery(self, q, *args):
        cu = self.engine.execute(q, *args)
        return cu

    def setwhere(self,startdate=None,enddate=None,range=None,offset=None, span=None):
        """Set the time frame for queries, either using absolute start and end dates,
           or something like range='week', span=1, for the last 7 days
           with offset=3 it will show you 10 days ago to 3 days ago"""

        self.startdate = self.enddate = None

        if offset is None:
            offset=0
        if span is None:
            span=1
        ret=""
        if not (startdate or enddate or range or offset or span!=1):
            startdate = datetime.datetime.today()

        now = datetime.datetime.now()

        allowed = set(["minutes", "hours","days","months","weeks"])
        if range and range+'s' in allowed:
            range = range + 's'
        if range in allowed:
            kw = {range: span+offset}
            delta_start = datetime.timedelta(**kw)
            startdate = now - delta_start

            if offset:
                kw = {range: offset}
                delta_end = datetime.timedelta(**kw)
                enddate = now - delta_end

        self.where_args=[]
        if startdate:
            ret += "timestamp >= %s"
            self.startdate=str(startdate)
            self.where_args.append(str(startdate))

            if enddate:
                ret += " AND timestamp < %s "
                self.enddate=str(enddate)
                self.where_args.append(str(enddate))

            self.where=ret
            return
            
        #else :
        #    ret += "timestamp = (select max(timestamp) from event)"
        self.where=ret

    def _fix_where(self):
        e = self.current_table.c
        self.where_clause = []
        if self.startdate:
            self.where_clause.append(e.timestamp >= self.startdate)
            if self.enddate:
                self.where_clause.append(e.timestamp <= self.enddate)

    def setlimit(self,limit=None):
        #left over function, not really needed
        """Set the limit for the number of rows to be returned
           call with no arguments to remove the limit"""
        self.limit=limit

    def find(self, sig=None, sig_id=None, src=None, dst=None, host=None, hostpair=None, data=None, proto=None, sport=None, dport=None,sid=None, idpair=None):
        """Search for any matching events. All critera are ANDed together"""
        if data:
            t = Table('event_simple_by_event_with_data', self.metadata,autoload=True)
        elif src or dst or host or hostpair:
            t = Table('event_simple_by_ip', self.metadata,autoload=True)
        else:
            t = Table('event_simple_by_event', self.metadata,autoload=True)
        self.current_table = t
        self._fix_where()
        e = t.c

        clauses = list(self.where_clause)
        if sig:
            s = '%' + sig + '%'
            clauses.append(e.sig.op("ILIKE")(s))

        if sig_id:
            clauses.append(e.sig_id==sig_id)
            
        if src:
            ip=IPy.IP(src)
            if ip.len() == 1:
                ip = ip.int()
                clauses.append(e.ip_src==ip)
            else :
                first, last = ip[0].int(), ip[-1].int()
                clauses.append(e.ip_src >= first)
                clauses.append(e.ip_src <= last)
        if dst:
            ip=IPy.IP(dst)
            if ip.len() == 1:
                ip = ip.int()
                clauses.append(e.ip_dst==ip)
            else :
                first, last = ip[0].int(), ip[-1].int()
                clauses.append(e.ip_dst >= first)
                clauses.append(e.ip_dst <= last)
        if host:
            ip=IPy.IP(host)
            if ip.len() == 1:
                ip = ip.int()
                clauses.append(or_(e.ip_src==ip,e.ip_dst==ip))
            else :
                first, last = ip[0].int(), ip[-1].int()
                sqlargs.extend([a,b,a,b])
                clauses.append(or_( and_(e.ip_src >= first, e.ip_src <= last ),
                                    and_(e.ip_dst >= first, e.ip_dst <= last )
                              ))

        if hostpair:
            src, dst = hostpair
            a = IPy.IP(src).int()
            b = IPy.IP(dst).int()
            clauses.append(or_( and_(e.ip_src == a, e.ip_dst == b ),
                                and_(e.ip_src == b, e.ip_dst == a )
                          ))
        if data:
            data = binascii.hexlify(data).upper()
            s = '%' + data + '%'
            clauses.append(e.data.like(s))

        if proto:
            clauses.append(e.proto==proto)
        if sport:
            sport = int(sport)
            clauses.append(e.sport==sport)
        if dport:
            dport = int(dport)
            clauses.append(e.dport==dport)

        if sid:
            clauses.append(e.sid==sid)

        if idpair:
            sid,cid = idpair
            clauses = []
            clauses.append(e.sid==sid)
            clauses.append(e.cid==cid)


        data = t.select(whereclause = and_(*clauses),
                                    limit=self.limit,
                                    order_by = [e.timestamp,e.cid],
                                    ).execute()

        for x in data:
            x=dict(x)
            if x['data']:
                x['data']=binascii.unhexlify(x['data'])
            x['ip_src']=IPy.IP(x['ip_src'])
            x['ip_dst']=IPy.IP(x['ip_dst'])
            yield x

    def group(self, min=None, group='ip_src', ungroup='sig', *args, **kwargs):
        data=list(self.find(*args, **kwargs))

        groups={}
        for event in data:
            g=event[group]
            if g not in groups:
                groups[g]=[]
            groups[g].append(event)

        for g, c in count([x[group] for x in data]):
            ent={}
            ent[group]=g
            ent['count']=c
            l=[]
            if ungroup is None:
                for alert in groups[g]:
                    l.append((1,alert))
            else :
                for alert, c in count([x[ungroup] for x in groups[g]]):
                    if not min or c >= min:
                        l.append((c,alert))
            if not l:
                continue
            ent['list']=l
            yield ent
        
    def grouptest(self, min=None, group='ip_src', ungroup='sig', *args, **kwargs):
        data=self.group(min=min, group=group, ungroup=ungroup, *args, **kwargs)

        for x in data:
            print x[group],x['count']
            for count,alert in x['list']:
                print "   ", count, alert


    def getstream(self, src, dst):
        return self.find(hostpair=(src,dst))


    def signatures(self):
        """Return a list of dictionaries of signatures, last hits, and source and dest counts"""
        q="""
        SELECT s.sig_id, s.sig_name as sig,  COUNT(s.sig_id),
            MAX(timestamp) as max_time,
            COUNT(DISTINCT ip_src) as sources,
            COUNT(DISTINCT ip_dst) as dests
        FROM signature s, event e
            LEFT JOIN iphdr i on i.cid = e.cid and i.sid = e.sid
        WHERE %s
        AND e.signature = s.sig_id
        GROUP BY sig_id, sig_name ORDER BY COUNT(signature) DESC
        """ % self.where

        return self._dictquery(q, *self.where_args)

    def get_attackers(self, sigs):
        """For each of the sigs, return src_ip, sig, number of alerts, number of destination subnets"""
        t = Table('event_simple_by_event', self.metadata,autoload=True)
        self.current_table = t
        self._fix_where()
        e = t.c
        clauses = list(self.where_clause)
        clauses.append(or_(*[e.sig==s for s in sigs]))
        data = select(
            [e.ip_src,
             e.sig,
             func.count(e.ip_dst).label("alerts"),
             func.count(func.distinct(e.ip_dst/256)).label("subnets")],
            whereclause = and_(*clauses),
            group_by=[e.ip_src,e.sig]
            ).execute()
        for x in data:
            x=dict(x)
            x['ip_src']=IPy.IP(x['ip_src'])
            yield x

    def get_events_for_ip(self, ip):
        ip_int = IPy.IP(ip).int()

        t = Table('event_simple_by_ip', self.metadata,autoload=True)
        self.current_table = t
        self._fix_where()
        e = t.c
        clauses = list(self.where_clause)
        clauses.append(or_(e.ip_src==ip_int, e.ip_dst==ip_int))
        return select(
            [e.sig, func.count(e.sig).label("count"), func.min(e.timestamp).label("first"), func.max(e.timestamp).label("last")],
            whereclause = and_(*clauses),
            group_by = [e.sig],
            ).execute()

    def get_last_event_time_for_sensor(self, sensor):
        q = "select max(e.timestamp) from event e where sid=(select s.sid from sensor s where s.hostname=%s)"
        qq = self.engine.execute(q, sensor)
        return qq.fetchall()[0][0]

import operator
def count(it):
    d={}
    for x in it:
        d[x]=d.get(x,0)+1

    l = d.items()
    l.sort(key=operator.itemgetter(1),reverse=True)
    return l

