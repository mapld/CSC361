import dpkt
import socket
import datetime

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

f = open('sample-capture-file', 'rb')
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


    # connection data needed for a packet
    connection_data = {
        'ts' : ts,
        'source_port' : source_port,
        'dest_port' : dest_port,
        'source_ip' : source_ip,
        'dest_ip' : dest_ip,
        'flags' : tcp_obj.flags
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

print("---------------------------------------------")
print("Total connections: ", num_connections)
print("Number of complete connections: ", complete_connections)
print("Number of reset connections: ", reset_connections)
print("Number of connections still open: ", num_connections - complete_connections)

mean_complete_time = complete_time_sum / complete_connections
print("Max time open for a complete connection: ", max_complete_time)
print("Min time open for a complete connection: ", min_complete_time)
print("Mean time open for complete connections: ", mean_complete_time)

