import ssl
import socket
import re
import argparse
import sys

RECV_BUFFER_SIZE = 2048

def check_http2(host):
    connect_port = 443
    ip = socket.gethostbyname(host)

    so = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/1.1'])

    so = context.wrap_socket(so, server_hostname=host)

    so.connect((ip,connect_port))

    if so.selected_alpn_protocol() == "h2":
        so.close()
        return True
    so.close()
    return False

def connect(host, path = "/", ip=None, use_ssl=False, so=None, debug=False, http_version="HTTP/1.1"):
    # print("Info: ")
    # print(host)
    # print(path)
    # print(use_ssl)
    # print(so)
    # print(debug)
    # print(" ")

    connect_port = 80
    if use_ssl:
        connect_port = 443

    ip = socket.gethostbyname(host)

    if not so:
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if use_ssl:
            so = ssl.wrap_socket(so);
        so.connect((ip,connect_port))

    # request = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\nConnection: Upgrade, HTTP2-Settings" + "\r\nUpgrade: " + h2_header + "\r\nHTTP2-Settings:" + "\r\n\r\n"
    request = "GET " + path + " " + http_version  + "\r\nHost: " + host + "\r\nUser-Agent: curl/7.35.0" "\r\n\r\n"

    if(debug):
        print("Request: ")
        print(repr(request))

    so.sendall(request.encode())

    reply = so.recv(RECV_BUFFER_SIZE)

    reply = reply.decode()

    so.close()

    match_redirect = re.search(r'(302)|(301) ', reply)
    match_OK = re.search(r'200 ', reply)
    if match_redirect:
        if(debug):
            print(reply)
        match = re.search(r'Location: http(s*)://((.+\.)*.*?)(/.*)', reply)
        if(not match):
            print("Failed to parse location from reply")
            print(reply)
            return
        if(not match.group(1)):
            use_ssl = False
        new_host = match.group(2)
        if(debug):
            print("Redirecting to: " + new_host)
        if(match.group(4)):
            path=match.group(4)
            path=path.rstrip()
        if(debug):
            print("Path: " + path);
        so.close()
        connect(host=new_host, use_ssl=use_ssl, ip=ip, path=path, debug=debug)
        return
    elif match_OK:
        if(debug):
            print(reply);
        if(use_ssl):
            print("1. Support of HTTPS: yes")
        else:
            print("1. Support of HTTPS: no")
        if(use_ssl and check_http2(host)):
            print("2. Newest HTTP version supported by server: 2.0")
        else:
            print("2. Newest HTTP version supported by server: 1.1")
        matches = re.finditer(r'Set-Cookie: (.*?)=(.*?);(.*)', reply)
        print("3. List of cookies:")
        for match in matches:
            print("\nKey: ", match.group(1))
            domain_match = re.search(r'domain=(.*?)(;|$)', match.group(0))
            if(domain_match):
                print("Domain: ", domain_match.group(1))
            else:
                print("Domain: ", host, " (no domain given with cookie)")

    else:
        match_V = re.search(r'(505) ', reply);
        match_not_found = re.search(r'(404) ', reply);
        if(match_V):
            if http_version == "HTTP/1.1":
                connect(host=host, use_ssl=use_ssl, ip=ip, path=path, debug=debug, http_version="HTTP/1.0")
            print ("Error 505: HTTP Version Not Supported")
        elif(match_not_found):
            print ("Error 404: Not Found")
        else:
            print("Unexpected Error")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Query a server for information')
    parser.add_argument('hostname')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    hostname = args.hostname
    debug = args.debug
    print("website:", hostname)
    try:
        connect(host=hostname, use_ssl=True, debug=debug)
    except Exception as e:
        print("Unexpected error: ", type(e))
        if(debug):
            print(e)
