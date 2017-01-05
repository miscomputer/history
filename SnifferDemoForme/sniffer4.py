# coding:utf-8
import pcap,dpkt
import time,logging

p = pcap.pcap()
# p.setfilter('tcp port 8080')
nowtime = time.strftime('%H.%M.%S',time.localtime(time.time()))
header_list = []
logging.basicConfig(level=logging.DEBUG,
                    format='%(filename)s\r\n%(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='c:\\tmp\\sniffer_%s.log' % nowtime,
                    filemode='w')

for ptime,pdata in p:
    p = dpkt.ethernet.Ethernet(pdata)
    ip = p.data
    nowtime = time.strftime('%H:%M:%S',time.localtime(ptime))
    if ip.__class__.__name__ == 'IP':
        dst_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
        src_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
        tcp = ip.data
        # dport = tcp.dport
        if tcp.__class__.__name__ == 'TCP' and src_ip == '10.74.121.42' and dst_ip == '10.187.162.202' and len(tcp.data) > 1:
            dport = tcp.dport
            sport = tcp.sport
            received_string = str(tcp.data)
            http_method = ''
            http_url = ''
            http_body = ''
            http_headers = ''
            # print received_string
            try:
                rs = dpkt.http.Request(received_string)
                http_method = rs.method
                http_url = rs.uri
                http_body = rs.body
                http_headers = rs.headers
                if http_method == 'POST' and 'upload_client_log' in http_url:
                    print nowtime
                    print '%s:%s' % (http_method,http_url)
                    print 'dstport(%s) : src port(%s)' % (dport,sport)
                    print 'body :', http_body
                    print 'headers :', http_headers
                    # logging.info(http_headers)
                    logging.info(http_body)
                    # print logging.info('-------------------------------------------------\r\n')
            except:
                # print received_string
                pass