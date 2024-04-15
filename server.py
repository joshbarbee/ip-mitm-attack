import http.server
import ssl
import threading

def make_https():
    server_address = ('', 443)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="certificates/cert.pem", keyfile="certificates/key.pem")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

def make_http():
    server_address = ('', 80)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.serve_forever()

http_thread = threading.Thread(target=make_http)
https_thread = threading.Thread(target=make_https)

http_thread.start()
https_thread.start()

try:
    while True:
        ...
except KeyboardInterrupt:
    https_thread.join()
    http_thread.join()