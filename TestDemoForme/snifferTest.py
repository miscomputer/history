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
        if tcp.__class__.__name__ == 'TCP' and src_ip == '10.74.121.42' and dst_ip == '10.74.121.42' and len(tcp.data) > 1:
            dport = tcp.dport
            sport = tcp.sport
            # if dport != 80000:
            #     str_start = tcp.data.find('{')
            #     str_end = str(str_start).find('\r\n')
            #     json_str = tcp.data[str_start:str_end]
            #     # print json_str
            try:
                response = dpkt.http.Response(tcp.data)
                res_headers = response.headers
                res_body = response.body
                res_reason = response.reason
                if 'getconf'in res_body:
                    print 'header:',res_headers
                    print 'body:',res_body
                    print 'reason:',res_reason
                    print '%s ---> %s' % (src_ip,dst_ip)
            except:
                pass
                # print tcp