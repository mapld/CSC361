import dpkt
import socket
import datetime
import argparse


def reportOnFile(filename):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)


    count = 1
    for ts, buf in pcap:
        ethernet_obj = dpkt.ethernet.Ethernet(buf)
        ip_obj = ethernet_obj.data

        if not isinstance(ethernet_obj.data, dpkt.ip.IP):
            print("Packet " + str(count) + " not an IP packet")
            continue
        source_ip = socket.inet_ntoa(ip_obj.src)
        dest_ip = socket.inet_ntoa(ip_obj.dst)
        print("Packet " + str(count) + ":: source ip: " + source_ip + ", dest ip: " + dest_ip)
        count += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read a cap file and report information on intermediate hosts and fragmentation details')
    parser.add_argument('filename')
    args = parser.parse_args()
    filename = args.filename

    reportOnFile(filename)
