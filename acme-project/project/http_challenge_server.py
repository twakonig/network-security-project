from flask import Flask     # microframework for web applications
from threading import Thread

"""

*** Challenge HTTP server ***

    FUNCTIONALITY:
    - provide a HTTP server that can respond to challenges from the ACME server
    - ACME server will direct all http-01 challenges to this port
    - runs on TCP port 5002

"""

http_chall_server = Flask(__name__)
PORT = 5002

# store challenge value in memory
keys = {}

@http_chall_server.route("/.well-known/acme-challenge/<token>")
def respond_to_challenge(token):
    if token in keys:
        return keys[token]
    else:
        return "no challenge found"

def add_challenge(token, auth_string):
    # store auth_strings in memory
    keys[token] = auth_string
    

def start_chall_server(record):
    server_t = Thread(target=lambda: http_chall_server.run(
        host=record, port=PORT, debug=False, threaded=True))
    #browser_thread.daemon = True
    server_t.start()