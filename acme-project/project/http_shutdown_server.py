from flask import Flask, request   
from threading import Thread
import argparse

"""

*** Shutdown HTTP server ***

    FUNCTIONALITY:
    - provide a HTTP server that can be used to shutdown the ACME client
    - applccation should terminate itself when GET /shutdown is received
    - runs on TCP port 5003

"""

http_shutdown_server = Flask(__name__)
PORT = 5003

@http_shutdown_server.route("/shutdown")
def shutdown_all():
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if shutdown is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    shutdown()
    return "Shutting down ACME client..."


def start_shutdown_server(record):
    server_t = Thread(target=lambda: http_shutdown_server.run(
        host=record, port=PORT, debug=False, threaded=True))
    #browser_thread.daemon = True
    server_t.start()
    return server_t

