from flask import Flask  
from threading import Thread 
import argparse

"""

*** Certificate HTTPS server ***

    FUNCTIONALITY:
    - upon GET / request, should serve certificate
    - server should serve full certificate chain obtained from the ACME server (including intermediate certificates)
    - runs on TCP port 5001

"""

https_certificate_server = Flask(__name__)
PORT = 5001

# return certificate upon request
# TODO: is it a GET request? or POST?
@https_certificate_server.route("/", methods=['GET'])
def secure_webpage(token):
    # return certificate
    with open("certificate.pem", "rb") as f:
        certificate = f.read()
    return certificate


def start_https_server(record):
    server_t = Thread(target=lambda: https_certificate_server.run(
        host=record, port=PORT, debug=False, threaded=True, ssl_context=("certificate.pem", "private_key.pem")))
    #browser_thread.daemon = True
    server_t.start()