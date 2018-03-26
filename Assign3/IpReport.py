import dpkt
import socket
import datetime
import argparse
import statistics

def isValidOutgoing(data):
    if isinstance(data, dpkt.udp.UDP):
        return True
    if isinstance(data, dpkt.icmp.ICMP) and data.type == 8:
        return True
    return False

def reportOnFile(filename):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # the highest ttl packet sent out to this point
    ttl_counter = 0
    source_node_ip = ""
    ultimate_dest_ip = ""

    intermediate_ips = []
    intermediate_ips_set = set()
    outgoing_packets = {}

    ttl_counts = [0] * 100

    ttl_probe_count = 0 # how many probes used "per ttl"

    datagrams = {}
    frag_id_map = {}

    # contains list of all protocols found in trace file
    protocols = set()

    base_ts = 0

    count = 0
    for ts, buf in pcap:
        if count == 0:
            base_ts = ts

        ethernet_obj = dpkt.ethernet.Ethernet(buf)
        ip_obj = ethernet_obj.data

        count += 1

        # print("packet ", count, ", type:", type(ip_obj.data))

        if not isinstance(ethernet_obj.data, dpkt.ip.IP):
            # print("Packet " + str(count) + " not an IP packet")
            continue

        protocols.add(ip_obj.p)

        source_ip = socket.inet_ntoa(ip_obj.src)
        dest_ip = socket.inet_ntoa(ip_obj.dst)
        # print("Packet " + str(count) + ":: source ip: " + source_ip + ", dest ip: " + dest_ip)

        cur_ttl = ip_obj.ttl
        if cur_ttl < ttl_counter:
            # print("WARNING: out of order packet", count)
            continue

        print(cur_ttl)
        # if cur_ttl == ttl_counter:
        #     print("Another packet with ttl ", cur_ttl)
        if cur_ttl == ttl_counter + 1 and isValidOutgoing(ip_obj.data):
            # print("Sent packet with ttl ", cur_ttl)
            ttl_counter = cur_ttl
            if ttl_counter == 1:
                source_node_ip = source_ip
                ultimate_dest_ip = dest_ip

        if cur_ttl == ttl_counter and isValidOutgoing(ip_obj.data) and ttl_counter == 1:
            ttl_probe_count += 1

        if source_ip == source_node_ip and dest_ip == ultimate_dest_ip and cur_ttl <= ttl_counter+1: # from source node
            frag_id = ip_obj.id
            more_fragments = bool(ip_obj.off & dpkt.ip.IP_MF)
            frag_offset = (ip_obj.off & dpkt.ip.IP_OFFMASK)*8
            if frag_id not in datagrams:
                datagrams[frag_id] = {'count':0, 'offset':0, 'send_times':[]}
            if more_fragments or frag_offset > 0:
                datagrams[frag_id]['count'] += 1
                datagrams[frag_id]['offset'] = frag_offset
            datagrams[frag_id]['send_times'].append(ts)

            intermediate_ips.append("") # placeholder to be filled in
            intermediate_ips.append("") # placeholder to be filled in
            intermediate_ips.append("") # placeholder to be filled in
            intermediate_ips.append("") # placeholder to be filled in
            intermediate_ips.append("") # placeholder to be filled in
            if isinstance(ip_obj.data, dpkt.udp.UDP):
                udp_obj = ip_obj.data
                frag_id_map[udp_obj.dport] = frag_id

                # record that an outgoing udp request has been sent to a specific port
                print(ip_obj.ttl)
                outgoing_packets[udp_obj.dport] = {'ttl':ip_obj.ttl, 'ttl_adj':ttl_counts[ip_obj.ttl]}
                ttl_counts[ip_obj.ttl] += 1

            if isinstance(ip_obj.data, dpkt.icmp.ICMP) and ip_obj.data.type == 8:
                icmp_obj = ip_obj.data
                frag_id_map[icmp_obj['echo'].seq] = frag_id

                outgoing_packets[icmp_obj['echo'].seq] = {'ttl':ip_obj.ttl, 'ttl_adj':ttl_counts[ip_obj.ttl]}
                ttl_counts[ip_obj.ttl] += 1


        elif dest_ip == source_node_ip: # back to source node


            if isinstance(ip_obj.data, dpkt.udp.UDP):
                udp_obj = ip_obj.data
            elif isinstance(ip_obj.data, dpkt.icmp.ICMP):
                icmp_obj = ip_obj.data
                icmp_type = icmp_obj.type
                data_packet = icmp_obj.data
                if icmp_type == 8 or icmp_type == 0:
                    # handle ping reply case
                    seq = data_packet.seq
                    outgoing_packets[seq]['reply_time'] = ts
                    outgoing_packets[seq]['ip'] = source_ip
                    outgoing_packets[seq]['frag_id'] = frag_id_map[seq]
                    continue
                data_packet = icmp_obj.data.data.data
                if isinstance(data_packet, dpkt.udp.UDP) and data_packet.dport in outgoing_packets:
                    outgoing_packets[data_packet.dport]['reply_time'] = ts
                    outgoing_packets[data_packet.dport]['ip'] = source_ip
                    outgoing_packets[data_packet.dport]['frag_id'] = frag_id_map[data_packet.dport]
                    if icmp_type == 11:
                        # print("Response from intermediate node", data_packet.dport)
                        if source_ip not in intermediate_ips_set:
                            ttl = outgoing_packets[data_packet.dport]['ttl']
                            ttl_adj = outgoing_packets[data_packet.dport]['ttl_adj']
                            intermediate_ips[(ttl*5)-1+ttl_adj] = source_ip
                            intermediate_ips_set.add(source_ip)

                    #     print("Response from final node", data_packet.dport)
                if isinstance(data_packet, dpkt.icmp.ICMP) and data_packet['echo'].seq in outgoing_packets:
                    seq = data_packet['echo'].seq
                    outgoing_packets[seq]['reply_time'] = ts
                    outgoing_packets[seq]['ip'] = source_ip
                    outgoing_packets[seq]['frag_id'] = frag_id_map[seq]
                    if icmp_type == 11:
                        if source_ip not in intermediate_ips_set:
                            ttl = outgoing_packets[seq]['ttl']
                            ttl_adj = outgoing_packets[seq]['ttl_adj']
                            intermediate_ips[(ttl*5)-1+ttl_adj] = source_ip
                            intermediate_ips_set.add(source_ip)
        else:
            # print("Ignoring packet not to or from source node")
            continue

    # remove empty strings from ip list (packets sent out which didn't return from an intermediate host)
    while "" in intermediate_ips: intermediate_ips.remove("")

    rdata = {}
    rdata['ttl_probe_count'] = ttl_probe_count
    rdata['intermediate_ips'] = intermediate_ips_set

    print("")

    print("Source IP: ", source_node_ip)
    print("Destination IP: ", ultimate_dest_ip)
    print("Intermediate IPs:")
    for ip in intermediate_ips:
        print(ip)

    print("")
    print("Protocols found in trace: ")
    #table containing names for all the protocol numbers
    protocol_table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
    for protocol in protocols:
        print(protocol_table[protocol])

    print("")
    print("Datagrams:")
    for id,datagram in datagrams.items():
        print("Datagram " + str(id) + ": " + str(datagram["count"]) + " fragments, final offset: " + str(datagram["offset"]))

    ip_rtts = {}
    for port,packet in outgoing_packets.items():
        if 'frag_id' not in packet:
            continue
        frag_id = packet['frag_id']
        send_times = datagrams[frag_id]['send_times']
        if 'reply_time' not in packet:
            continue
        reply_time = packet['reply_time']
        ip = packet['ip']
        if ip not in ip_rtts:
            ip_rtts[ip] = []
        for send_time in send_times:
            ip_rtts[ip].append(reply_time - send_time)

    print("")
    rtt_counter = 0
    rdata['rtt_means'] = []
    for ip, rtts in ip_rtts.items():
        print("Average rtt for ip ", ip, ": ", statistics.mean(rtts))
        rdata['rtt_means'].append( statistics.mean(rtts))
        print("Stddev rtt for ip ", ip, ": ", statistics.pstdev(rtts))

    return rdata

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read a cap file and report information on intermediate hosts and fragmentation details')
    parser.add_argument('filename')
    args = parser.parse_args()
    filename = args.filename

    reportOnFile(filename)
