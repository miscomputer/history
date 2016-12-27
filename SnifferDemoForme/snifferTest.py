# coding:utf-8
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
        if tcp.__class__.__name__ == 'TCP' and src_ip == '10.187.162.202' and len(tcp.data) > 1:
            dport = tcp.dport
            # if dport == 443:
            print '%s ---> %s:%s' % (src_ip, dst_ip, dport)
            # headers = dpkt.http.parse_headers(tcp.data)
            str_start = tcp.data.find('{')
            str_end = str(str_start).find('\r\n')
            json_str = tcp.data[str_start:str_end-1]
            print json_str
