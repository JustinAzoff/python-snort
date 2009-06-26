drop view event_simple_by_event;
CREATE view event_simple_by_event
AS
SELECT e.cid, e.sid, e.timestamp, s.sig_id, s.sig_name as sig, d.data_payload as data, i.ip_src, i.ip_dst,
        COALESCE(tcp_dport, udp_dport) as dport,
        COALESCE(tcp_sport, udp_sport) as sport,
        CASE WHEN tcp_dport is not null THEN 'tcp'
             WHEN udp_dport is not null then 'udp' ELSE 'icmp'
             END as proto,
        ip_proto, ip_len
        FROM iphdr i, signature s, event e
        LEFT JOIN data   d on d.cid = e.cid and d.sid = e.sid
        LEFT JOIN tcphdr t on t.cid = e.cid and t.sid = e.sid
        LEFT JOIN udphdr u on u.cid = e.cid and u.sid = e.sid
        WHERE
            i.cid = e.cid and i.sid = e.sid AND
            e.signature = s.sig_id
        ORDER BY e.timestamp ASC, e.cid ASC
;
drop view event_simple_by_ip;
CREATE view event_simple_by_ip
AS
SELECT i.cid, i.sid, e.timestamp, e.signature as sig_id, s.sig_name as sig, d.data_payload as data, i.ip_src, i.ip_dst,
        COALESCE(tcp_dport, udp_dport) as dport,
        COALESCE(tcp_sport, udp_sport) as sport,
        CASE WHEN tcp_dport is not null THEN 'tcp'
             WHEN udp_dport is not null then 'udp' ELSE 'icmp'
             END as proto,
        ip_proto, ip_len
        FROM signature s, event e, iphdr i
        LEFT JOIN data   d on d.cid = i.cid and d.sid = i.sid
        LEFT JOIN tcphdr t on t.cid = i.cid and t.sid = i.sid
        LEFT JOIN udphdr u on u.cid = i.cid and u.sid = i.sid
        WHERE
            i.cid = e.cid and i.sid = e.sid AND
            e.signature = s.sig_id
        ORDER BY e.timestamp ASC, i.cid ASC

;
drop view event_simple_by_event_with_data;
CREATE view event_simple_by_event_with_data
AS
SELECT e.cid, e.sid, e.timestamp, s.sig_id, s.sig_name as sig, d.data_payload as data, i.ip_src, i.ip_dst,
        COALESCE(tcp_dport, udp_dport) as dport,
        COALESCE(tcp_sport, udp_sport) as sport,
        CASE WHEN tcp_dport is not null THEN 'tcp'
             WHEN udp_dport is not null then 'udp' ELSE 'icmp'
             END as proto,
        ip_proto, ip_len
        FROM iphdr i, signature s, data d, event e
        LEFT JOIN tcphdr t on t.cid = e.cid and t.sid = e.sid
        LEFT JOIN udphdr u on u.cid = e.cid and u.sid = e.sid
        WHERE
            i.cid = e.cid and i.sid = e.sid AND
            e.signature = s.sig_id AND
            d.cid = e.cid and d.sid = e.sid
        ORDER BY e.timestamp ASC, e.cid ASC
;
