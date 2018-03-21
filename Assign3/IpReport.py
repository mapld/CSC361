import dpkt
import socket
import datetime
import argparse


def reportOnFile(filename):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        ethernet_obj = dpkt.ethernet.Ethernet(buf)
        ip_obj = ethernet_obj.data

        print(ip_obj.src)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read a cap file and report information on intermediate hosts and fragmentation details')
    parser.add_argument('filename')
    args = parser.parse_args()
    filename = args.filename

    reportOnFile(filename)
