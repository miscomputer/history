import pcap,dpkt

p = pcap.pcap()
# p.setfilter('tcp port 8080')

header_list = []
for _,pdata in p:
    p = dpkt.ethernet.Ethernet(pdata)
    ip = p.data
    if ip.__class__.__name__ == 'IP':
        dst_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
        src_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
        tcp = ip.data
        # dport = tcp.dport
        if tcp.__class__.__name__ == 'TCP' and src_ip == '10.74.121.42' and dst_ip == '10.74.121.42' and len(tcp.data) > 1:
            dport = tcp.dport
            sport = tcp.sport
            received_string = str(tcp.data)
            try:
                rs = dpkt.http.Request(received_string) #参考 dpkt_doc
                http_method = rs.method
                http_url = rs.uri
                if 'setting' in http_url:
                    print '%s:%s' % (http_method,http_url)
                    print 'dstport(%s) : src port(%s)' % (dport,sport)
            except:
                # print received_string
                pass
