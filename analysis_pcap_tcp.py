import dpkt
import socket
import struct
class Packet:
    def __init__(self, ts, src, dst, sport, dport, seq, ack, flags, win, payload_len, total_length):
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
        self.total_length = total_length

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

        self.closed = False
        self.fin_seen = set()

    # put a packet in the flow 
    def add_packet(self, pkt: Packet):
        self.packets.append(pkt)
        if self.flow_start is None:
            self.flow_start = pkt.ts
        self.flow_end = pkt.ts
        self.sender_bytes += pkt.payload_len
        if pkt.flags & dpkt.tcp.TH_FIN:
            self.fin_seen.add(pkt.src)
            if len(self.fin_seen) == 2:
                self.closed = True
        if pkt.flags & dpkt.tcp.TH_RST:
            self.closed = True

    def sender_packets(self):
        return [p for p in self.packets if p.src == self.src]

    def receiver_packets(self):
        return [p for p in self.packets if p.src == self.dst]
    def sender_throughput(self):
        sender_packets = self.sender_packets() 

        if not sender_packets:
            return 0

        #inital time stamp
        start_time = sender_packets[0].ts

        #get last ack
        receiver_packets = self.receiver_packets()
        receiver_acks = [p for p in receiver_packets if p.flags & dpkt.tcp.TH_ACK]
        end_time = receiver_acks[-1].ts

        total_bytes = sum(p.total_length for p in sender_packets)  # include TCP header 
        duration = end_time - start_time

        if duration <= 0:
            return 0

        return total_bytes / duration  # bytes per second
    def estimate_rtt(self):
        rtts = []
        acked_seq = 0

        sender_packets = self.sender_packets() 

        receiver_packets = self.receiver_packets()
        receiver_acks = [p for p in receiver_packets if p.flags & dpkt.tcp.TH_ACK]

        for s_pkt in sender_packets:
            # find first ack that recieves at least this packet
            for r_pkt in receiver_acks:
                if r_pkt.ack >= s_pkt.seq + s_pkt.payload_len:
                    rtts.append(r_pkt.ts - s_pkt.ts)
                    break  # move to next sender packet

        if rtts:
            return sum(rtts) / len(rtts)  
        else:
            return 0.05 #jic
    def estimate_cwnd(self, windows):
        rtt = self.estimate_rtt()
        # rtt = .5 #testing
        if rtt == 0:
            return []

        cwnd_estimates = []
        inflight = set()
        next_rtt_mark = self.flow_start + rtt

        for pkt in self.packets:
            if pkt.src == self.src:
                # add packet if sender
                inflight.add((pkt.seq, pkt.seq + pkt.payload_len))
            else:
                # subtract bytes and update if reciever
                if pkt.flags & dpkt.tcp.TH_ACK:
                    inflight = { (s, e) for (s, e) in inflight if e > pkt.ack } #remove all entries below ack
            # check if passed the next RTT mark
            if pkt.ts >= next_rtt_mark: # make it after every ack
                bytes_in_flight = sum(e - s for (s, e) in inflight)
                cwnd_estimates.append(bytes_in_flight)
                next_rtt_mark += rtt
                if len(cwnd_estimates) >= windows:
                    break

        return cwnd_estimates
    def __repr__(self):
        return (f"Flow({self.src}:{self.sport} -> {self.dst}:{self.dport}, "
                f"{len(self.packets)} packets)")

class Flows:
    def __init__(self, src, sport, dst, dport):
        self.list = []
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
    def add_packet(self, pkt: Packet):
        # if pkt.flags & dpkt.tcp.TH_SYN and not pkt.flags & dpkt.tcp.TH_ACK:
            # print("it wanna make a new list")
        if not self.list:
            if pkt.flags & dpkt.tcp.TH_SYN and not pkt.flags & dpkt.tcp.TH_ACK:
                self.list.append(Flow(self.src, self.sport, self.dst, self.dport))
            else:
                return  
        current_list = self.list[-1]
        if(current_list.closed):
            if pkt.flags & dpkt.tcp.TH_SYN and not (pkt.flags & dpkt.tcp.TH_ACK):
                self.list.append(Flow(pkt.src, pkt.sport, pkt.dst, pkt.dport))
                current_list = self.list[-1]
            else:
                # print("EPHEMERAL FLOW ERROR")
                return
        current_list.add_packet(pkt)
    def __repr__(self):
        out = ""
        for flow in self.list:
            out += str(flow)
        return out
        
class Flow_Table:
    def __init__(self):
        # {flow_id: Flow}
        self.flows = {}

    # frozenset makes it ambiguious which is source and dest (use the syn and ack to determine direction)
    @staticmethod
    def make_flows_id(src_ip, src_port, dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port)

    #it will make the flow if it doesnt exit
    def get_flows(self, src, sport, dst, dport): 
        fid = self.make_flows_id(src, sport, dst, dport)
        reverse_fid = self.make_flows_id(dst, dport, src, sport) 
        #this logic should be added to flows
        if fid not in self.flows:
            if reverse_fid in self.flows:
                fid = reverse_fid
            else:
                self.flows[fid] = Flows(src, sport, dst, dport)
        return self.flows[fid]

    def add_packet(self, pkt: Packet):
        #this will be changed to a call to flows' add packet
        flow = self.get_flows(pkt.src, pkt.sport, pkt.dst, pkt.dport)
        flow.add_packet(pkt)

    def all_flows(self):
        return list(self.flows.values())

    def __len__(self):
        return len(self.flows)

    def __repr__(self):
        sum = 0
        for flows in self.flows.values():
            sum += len(flows.list)
        return f"Flows(total_flows={sum})"
class TCPObject:
    def __init__(self, buffer):
        (self.sport, self.dport, self.seq, self.ack, offset_reserved, self.flags, self.win, self.chksum, self.urg_ptr) = struct.unpack("!HHLLBBHHH", buffer[:20])
        self.data_offset = (offset_reserved >> 4) * 4
        self.data = buffer[self.data_offset:]
class IPv4Packet:
    def __init__(self, buffer):
        ip_header = struct.unpack("!BBHHHBBH4s4s", buffer[:20]) #B is byte, H is short, 4s is 4 byte str
        version_ihl = ip_header[0]
        self.version = version_ihl >> 4 # last bytes are the version
        self.ihl = (version_ihl & 0xF) << 2 #in units of 4 bytes hence << 2
        self.total_length = ip_header[2] 
        self.protocol = ip_header[6]
        self.src = ip_header[8]
        self.dst = ip_header[9]
        self.payload = buffer[self.ihl:self.total_length]
        
        if(self.protocol == 6): # this is TCP maybe replace with constant
            self.data = TCPObject(self.payload)
class EthernetWrapper:
    def __init__(self, buffer):
        src_mac, dst_mac, type = struct.unpack("!6s6sH",buffer[:14])#unpack in network byte order, 6byte string *2, and a short
        self.src_mac = self.get_mac(src_mac)
        self.dst_mac = self.get_mac(dst_mac)
        self.payload = buffer[14:]

        if(type == dpkt.ethernet.ETH_TYPE_IP):
            self.type = "IP" #maybe i make an emum later
            self.data = IPv4Packet(self.payload)
        else:
            self.type = "UNKNOWN"
            self.data = self.payload
    def get_mac(self, bin_str):
        mac = ""
        for byte in bin_str:
            mac += f"{byte:02x}:"
        mac = mac[:-1]
        return mac
def read_pcap_tcp(pcap_file):
    flow_table = Flow_Table() #create flows obj

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth = EthernetWrapper(buf)
                if eth.type != "IP":
                    continue  # skip non-IP packets

                ip = eth.data
                if not isinstance(ip.data, TCPObject):
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
                total_length = tcp.data_offset + payload_len 
                # build Packet
                pkt = Packet(ts, src_ip, dst_ip, sport, dport, seq, ack, flags, win, payload_len, total_length)

                # add to Flows
                flow_table.add_packet(pkt)

            except Exception as e:
                print(f"Error processing packet: {e}")

    return flow_table
def get_throughput(flow: Flow):
    print(f"{flow.sender_throughput():.4f} bytes/second")
    return
def get_setup_info(flow: Flow):
    sender_packets = flow.sender_packets()
    sender_packets = sender_packets[2:4]
    for packet in sender_packets:
        print(packet)
    return 
def print_flow_info(flow_table):
    for flows in flow_table.flows.values():
        for flow in flows.list:
            print(flow)
            get_setup_info(flow)
            get_throughput(flow)
            print(flow.estimate_cwnd(3))
if __name__ == "__main__":
    flows = read_pcap_tcp("assignment2.pcap")
    print(flows)
    print_flow_info(flows)
