# coding:utf-8
import pcap,dpkt


class Capture:
    """
    分层解包
    """

    def __init__(self,pcap):
        self.pcap = pcap

    def __stream(self):
        for ptime,pdata in self.pcap:
            p = dpkt.ethernet.Ethernet(pdata)
            yield p.data

    def getIP(self):
        """互连层（IP）"""
        IPs = self.__stream()
        ips = dict.fromkeys(("dst_ip","src_ip"))
        for ip in IPs:
            if ip.__class__.__name__ == 'IP':
                ips["dst_ip"] = "%d.%d.%d.%d" % tuple(map(ord, list(ip.dst)))
                ips["src_ip"] = "%d.%d.%d.%d" % tuple(map(ord, list(ip.src)))
                yield ips,ip.data

    def getPort(self):
        """互连层（IP）"""
        IPs = self.__stream()
        Port = dict.fromkeys(("dport","sport"))
        for ip in IPs:
            if ip.__class__.__name__ == 'IP':
                if ip.data.__class__.__name__ == 'TCP':
                    Port["dport"] = ip.data.dport
                    Port["sport"] = ip.data.sport
                    yield Port

    def getTCP_request(self):
       #TODO 停不下来,还没思路
        """应用层（HTTP）"""
        TCPdata = dict.fromkeys(("body", "version", "method", "header", "uri"),None)
        TCPs = self.getIP()
        for TCP in TCPs:
            if TCP[1].__class__.__name__ == "TCP":
                # print TCP[2].data
                try:
                    rs = dpkt.http.Request(TCP[1].data)
                    TCPdata["body"] = rs.body
                    TCPdata["version"] = rs.version
                    TCPdata["method"] = rs.method
                    TCPdata["header"] = rs.headers
                    TCPdata["uri"] = rs.uri
                    print 'count',count
                except:
                    pass
                yield TCPdata

if __name__ == '__main__':
    p = pcap.pcap()
    p = Capture(p)

    # for i in p.getPort():
    #     print i

    for i in p.getTCP_request():
        print i['uri']
        print i
