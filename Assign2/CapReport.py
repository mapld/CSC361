import dpkt
import socket
import datetime
import argparse

# Defines a unique key representing a set of (ip:port,ip:port)
def getConnectionKey(source_port, dest_port, source_ip, dest_ip):
    connection_key = ""
    if(source_ip < dest_ip):
        connection_key += source_ip + ":"
        connection_key += str(source_port) + ":"
        connection_key += dest_ip + ":"
        connection_key += str(dest_port)
    else:
        connection_key += dest_ip + ":"
        connection_key += str(dest_port) + ":"
        connection_key += source_ip + ":"
        connection_key += str(source_port)
    return connection_key

def reportFromCapFile(filename):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    connections = {}

    for ts, buf in pcap:
        # go down the layers of the network stack
        ethernet_obj = dpkt.ethernet.Ethernet(buf)
        ip_obj = ethernet_obj.data
        tcp_obj = ip_obj.data

        source_port = tcp_obj.sport
        dest_port = tcp_obj.dport

        source_ip = socket.inet_ntoa(ip_obj.src)
        dest_ip = socket.inet_ntoa(ip_obj.dst)

        num_data_bytes = len(tcp_obj.data)

        seq_num = tcp_obj.seq
        ack_num = tcp_obj.ack

        recv_window_size = tcp_obj.win

        # connection data needed for a packet
        connection_data = {
            'ts' : ts,
            'source_port' : source_port,
            'dest_port' : dest_port,
            'source_ip' : source_ip,
            'dest_ip' : dest_ip,
            'flags' : tcp_obj.flags,
            'data_bytes' : num_data_bytes,
            'seq_num' : seq_num,
            'ack_num' : ack_num,
            'recv_window_size' : recv_window_size
        }
        connection_key = getConnectionKey(source_port, dest_port, source_ip, dest_ip)

        # sort packets into dictionary where each value is a list of packets
        if(connection_key not in connections):
            connections[connection_key] = []
        connections[connection_key].append(connection_data)

        num_connections = len(connections)

    counter = 1
    complete_connections = 0
    reset_connections = 0

    max_complete_time = 0
    min_complete_time = 10000000.0
    complete_time_sum = 0

    max_rtt = 0
    min_rtt = 100000000.0
    rtt_sum = 0
    rtt_count = 0

    max_packet_count = 0
    min_packet_count = 10000000.0
    packet_count_sum = 0

    max_recv = 0
    min_recv = 100000000.0
    recv_sum = 0
    recv_count = 0

    # loop over connections and then packets in each connection
    for key, packets in connections.items():
        print("==============================================================")
        print("Connection ", counter)
        counter += 1

        syn_count = 0
        fin_count = 0
        rst_count = 0
        for packet in packets:
            flags = packet['flags']
            syn_flag = ( flags & dpkt.tcp.TH_SYN ) != 0
            fin_flag = ( flags & dpkt.tcp.TH_FIN ) != 0
            ack_flag = ( flags & dpkt.tcp.TH_ACK ) != 0
            rst_flag = ( flags & dpkt.tcp.TH_RST ) != 0

            if(syn_flag):
                syn_count += 1
            if(fin_flag):
                fin_count += 1
            if(rst_flag):
                rst_count += 1

        rst_str = ""
        if(rst_count > 0):
            rst_str = "/R"
            reset_connections += 1
        print("Connection state: ", "S", syn_count, "F", fin_count, rst_str)


        connection_complete = (syn_count > 0 and fin_count > 0)
        if not connection_complete:
            print("Connection not complete")
            continue

        complete_connections += 1
        print("Connection is complete")

        first_syn_i = 0
        last_fin_i = -1
        for i in range(0,len(packets)):
            packet = packets[i]
            flags = packet['flags']
            syn_flag = ( flags & dpkt.tcp.TH_SYN ) != 0
            if(syn_flag):
                first_syn_i = i
                break

        for i in reversed(range(0,len(packets))):
            packet = packets[i]
            flags = packet['flags']
            fin_flag = ( flags & dpkt.tcp.TH_FIN ) != 0
            if(fin_flag):
                last_fin_i = i
                break

        start_time = packets[first_syn_i]['ts']
        end_time = packets[last_fin_i]['ts']
        duration = end_time - start_time
        print("Starting time: ", datetime.datetime.utcfromtimestamp(start_time))
        print("Ending time: ", datetime.datetime.utcfromtimestamp(end_time))
        print("Duration: ", duration, "seconds")

        max_complete_time = max(duration, max_complete_time)
        min_complete_time = min(duration, min_complete_time)
        complete_time_sum += duration

        # ip of the first packet, so we can sort into (this ip) and (not this ip)
        first_ip = packets[0]['source_ip']
        # other info
        first_port = packets[0]['source_port']
        other_ip = packets[0]['dest_ip']
        other_port = packets[0]['dest_port']

        packet_count = len(packets)

        max_packet_count = max(max_packet_count, packet_count)
        min_packet_count = min(min_packet_count, packet_count)
        packet_count_sum += packet_count

        # Calculate how many packets go in each direction
        first_count = 0
        first_data_bytes = 0
        other_data_bytes = 0
        for packet in packets:
            if packet['source_ip'] == first_ip:
                first_count += 1
                first_data_bytes += packet['data_bytes']
            else:
                other_data_bytes += packet['data_bytes']

        other_count = packet_count - first_count
        print("Packets sent from",
            first_ip + ":" + str(first_port),
            "to",
            other_ip + ":" + str(other_port),
            ":", first_count)
        print("Packets sent from",
            other_ip + ":" + str(other_port),
            "to",
            first_ip + ":" + str(first_port),
            ":", other_count)
        print("Total packet count: ", packet_count);

        print("Data bytes sent from",
            first_ip + ":" + str(first_port),
            "to",
            other_ip + ":" + str(other_port),
            ":", first_data_bytes)
        print("Data bytes sent from",
            other_ip + ":" + str(other_port),
            "to",
            first_ip + ":" + str(first_port),
            ":", other_data_bytes)
        print("Total data bytes: ", first_data_bytes + other_data_bytes);

        # map of ack number to ts
        packet_openings = {}
        for packet in packets:
            seq_num = packet['seq_num']
            ack_num = packet['ack_num']
            data_bytes = packet['data_bytes']
            ts = packet['ts']
            packet_openings[seq_num + data_bytes] = ts
            if ack_num in packet_openings:
                rtt_time = ts - packet_openings[ack_num]
                rtt_count += 1
                rtt_sum += rtt_time
                max_rtt = max(max_rtt, rtt_time)
                min_rtt = min(min_rtt, rtt_time)
                # print("RTT time: ", rtt_time)
                del packet_openings[ack_num]

        for packet in packets:
            recv = packet['recv_window_size']
            recv_count += 1
            recv_sum += recv
            min_recv = min(recv, min_recv)
            max_recv = max(recv, max_recv)

    print("---------------------------------------------")
    print("Total connections: ", num_connections)
    print("Number of complete connections: ", complete_connections)
    print("Number of reset connections: ", reset_connections)
    print("Number of connections still open: ", num_connections - complete_connections)

    mean_complete_time = complete_time_sum / complete_connections
    print("Max time open for a complete connection: ", max_complete_time)
    print("Min time open for a complete connection: ", min_complete_time)
    print("Mean time open for complete connections: ", mean_complete_time)

    mean_rtt = rtt_sum / rtt_count
    print("Max Round Trip Time: ", max_rtt)
    print("Min Round Trip Time: ", min_rtt)
    print("Mean Round Trip Time: ", mean_rtt)

    mean_packet_count = packet_count_sum / complete_connections
    print("Max packet count a complete connection: ", max_packet_count)
    print("Min packet count a complete connection: ", min_packet_count)
    print("Mean packet count for complete connections: ", mean_packet_count)

    mean_recv = recv_sum / recv_count
    print("Max recv window size: ", max_recv)
    print("Min recv window size: ", min_recv)
    print("Mean recv window size: ", mean_recv)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read a cap file and report details of the connections')
    parser.add_argument('filename')
    args = parser.parse_args()
    filename = args.filename

    reportFromCapFile(filename)
