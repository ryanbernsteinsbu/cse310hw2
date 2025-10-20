import dpkt
import socket
class Packet:
    def __init__(self, ts, src, dst, sport, dport, seq, ack, flags, win, payload_len):
        self.ts = ts
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.win = win
        self.payload_len = payload_len

    def __repr__(self):
        return (f"Packet(ts={self.ts:.6f}, src={self.src}:{self.sport}, "
                f"dst={self.dst}:{self.dport}, seq={self.seq}, ack={self.ack}, "
                f"flags={self.flags}, win={self.win}, len={self.payload_len})")


class Flow:
    def __init__(self, src, sport, dst, dport, packets=None):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.packets = [] if packets is None else packets

        self.flow_start = None
        self.flow_end = None
        self.sender_bytes = 0
        self.triple_dup_retx = 0
        self.timeout_retx = 0

    # put a packet in the flow 
    def add_packet(self, pkt: Packet):
        self.packets.append(pkt)
        if self.flow_start is None:
            self.flow_start = pkt.ts
        self.flow_end = pkt.ts
        self.sender_bytes += pkt.payload_len

    def sender_packets(self, sender_ip: str):
        return [p for p in self.packets if p.src == sender_ip]

    def receiver_packets(self, receiver_ip: str):
        return [p for p in self.packets if p.src == receiver_ip]

    def __repr__(self):
        return (f"Flow({self.src}:{self.sport} -> {self.dst}:{self.dport}, "
                f"{len(self.packets)} packets)")


class Flows:
    def __init__(self):
        # {flow_id: Flow}
        self.flows = {}

    # frozenset makes it ambiguious which is source and dest (use the syn and ack to determine direction)
    @staticmethod 
    def make_flow_id(src_ip, src_port, dst_ip, dst_port):
        return frozenset([(src_ip, src_port), (dst_ip, dst_port)])

    #it will make the flow if it doesnt exit
    def get_flow(self, src, sport, dst, dport): 
        fid = self.make_flow_id(src, sport, dst, dport)
        if fid not in self.flows:
            self.flows[fid] = Flow(src, sport, dst, dport)
        return self.flows[fid]

    def add_packet(self, pkt: Packet):
        flow = self.get_flow(pkt.src, pkt.sport, pkt.dst, pkt.dport)
        flow.add_packet(pkt)

    def all_flows(self):
        return list(self.flows.values())

    def __len__(self):
        return len(self.flows)

    def __repr__(self):
        return f"Flows(total_flows={len(self.flows)})"

def read_pcap_tcp(pcap_file):
    flows = Flows() #create flows obj

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue  # skip non-IP packets

                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue  # skip non-TCP

                tcp = ip.data

                #get ips
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)

                #get needed fields
                sport = tcp.sport
                dport = tcp.dport
                seq = tcp.seq
                ack = tcp.ack
                flags = tcp.flags
                win = tcp.win
                payload_len = len(tcp.data)

                # build Packet
                pkt = Packet(ts, src_ip, dst_ip, sport, dport, seq, ack, flags, win, payload_len)

                # add to Flows
                flows.add_packet(pkt)

            except Exception as e:
                print(f"Error processing packet: {e}")

    return flows

if __name__ == "__main__":
    flows = read_pcap_tcp("assignment2.pcap")
    print(flows)
