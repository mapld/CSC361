import ssl
import socket
import re

RECV_BUFFER_SIZE = 4096

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

def connect(host, ip=None, use_ssl=False, so=None):
    connect_port = 80
    if use_ssl:
        connect_port = 443

    if not ip:
        ip = socket.gethostbyname(host)

    if not so:
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if use_ssl:
            so = ssl.wrap_socket(so);
        so.connect((ip,connect_port))

    h2_header = "h2c"
    if use_ssl:
        h2_header = "h2"

    # request = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\nConnection: Upgrade, HTTP2-Settings" + "\r\nUpgrade: " + h2_header + "\r\nHTTP2-Settings:" + "\r\n\r\n"
    request = "HEAD / HTTP/1.1\r\n" + "Host: " + host +"\r\n\r\n"

    so.sendall(request.encode())

    reply = so.recv(RECV_BUFFER_SIZE)

    reply = reply.decode()

    so.close()

    match = re.search(r'302 (Found)|(Moved)', reply)
    if match:
        print(reply)
        match = re.search(r'Location: http.?://((.+\.)*.*)/.*', reply)
        new_host = match.group(1)
        print(new_host)
        so.close()
        connect(host=new_host, use_ssl=use_ssl)
        return
    else:
        print(reply);
        print("1. Support of HTTPS: yes")
        if(check_http2(host)):
            print("2. Newest HTTP version supported by server: 2.0")
        else:
            print("2. Newest HTTP version supported by server: 1.1")
        matches = re.finditer(r'Set-Cookie: (.*?)=(.*?);(.*)', reply)
        print("3. List of cookies:")
        for match in matches:
            print("\nKey: ", match.group(1))
            print("Value: ", match.group(2))
            domain_match = re.search(r'domain=(.*)', match.group(0))
            if(domain_match):
                print("Domain: ", domain_match.group(1))
            else:
                print("Domain: ", host, " (no domain given with cookie)")

hostname = "www.cbc.ca"
print("website:", hostname)
connect(host=hostname, use_ssl=True)
