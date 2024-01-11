from acme_client import AcmeClient
import argparse
import os
import sys
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dns_server import DnsServer
from http_shutdown_server import start_shutdown_server
from http_challenge_server import start_chall_server, add_challenge
from https_certificate_server import start_https_server


# start main()
def main():

    # parse commandline args
    parser = argparse.ArgumentParser(description='ACME client')
    parser.add_argumnent('challenge', help='Challenge type (http01 or dns01)')
    parser.add_argument('--dir', help='ACME Server Directory URL')
    parser.add_argument('--record', help='IPv4 address to be returned by DNS server for all A-record queries')
    parser.add_argument('--domain', action='append', required=True, help='Domain(s) for which to request a certificate. May provide multiple.')
    parser.add_argument('--revoke', action='store_true', required=False, help='Optional. Revoke certificate just after obtaining it.')
    # create args dictionary
    args = vars(parser.parse_args())


    # instantiate ACME client, creates account on ACME server
    acme_client = AcmeClient(args.get('dir'))

    # ----start challenge servers AND shutdown server in separate threads----
    # Shutdown Server
    shutdown_thread = start_shutdown_server(args.get('record'))
    
    # DNS Server
    dns_server = DnsServer(args.get('record'))
    dns_server.start_server()

    # HTTP challenge Server
    start_chall_server(args.get('record'))

    
    # prepare list of domains or single domain
    domains = args.get('domain')
    # request certificate for domain(s), receive authorization objects
    authorization_objects, order_url, finalize_url = acme_client.submit_certificate_order(domains)

    # rewrite challenge type given in command line args, quickfix
    challenge_type = args.get('challenge')
    if challenge_type == "dns01":
        challenge_type = "dns-01"
    elif challenge_type == "http01":
        challenge_type = "http-01"


    # --- iterate over authorization objects, perform challenge specified by command line ---
    for auth_url in authorization_objects:
        # get challenge (url, token, domain) of specific type and produce key authentication string
        challenge_url, challenge_token, domain = acme_client.fetch_challenges(auth_url, challenge_type)
        auth_string = acme_client.create_key_auth_string(challenge_token)

        # manipulate own resources (dns or http) according to challenge type
        if challenge_type == "dns-01":
            # do DNS challenge
            record_name = "_acme-challenge." + domain
            dns_server.new_txt_challenge(record_name, auth_string)

        elif challenge_type == "http-01":
            # do HTTP challenge
            add_challenge(challenge_token, auth_string)


        # notify ACME server after challenge performed
        status = acme_client.ready_for_challenge_validation(challenge_url)
        while status != "valid":
            status = acme_client.poll_for_status(auth_url)
            # wait 1 second
            time.sleep(1)

    # ------------------------------------------------------------------------------------


    
    # all authorization objects are valid, check whether order object is "ready"
    order_status = acme_client.poll_for_status(order_url)
    while order_status != "ready":
        order_status = acme_client.poll_for_status(order_url)
        time.sleep(1)

    # create CSR
    csr_key, csr_der = acme_client.create_csr(domains)

    # finalize order = send CSR to ACME server
    acme_client.finalize_order(finalize_url, csr_der)

    # poll unitl CA has signed the certificate: order object status is "valid"
    order_status = acme_client.poll_for_status(order_url)
    while order_status != "valid":
        order_status = acme_client.poll_for_status(order_url)
        time.sleep(1)

    # get certificate_url and download it
    certificate_url = acme_client.get_certificate_url(order_url)
    certificate = acme_client.download_certificate(certificate_url)


    # ---- store key and certificate to file ----
    with open("certificate.pem", "wb") as f:
        f.write(certificate)

    with open("private_key.pem", "wb") as f:
        f.write(csr_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # start certificate server (HTTPS) in separate thread, which can now read certificate and key from disk
    start_https_server(args.get('record'))

    # revoke certificate if --revoke flag is set
    if args.get('revoke'):
        certificate_x509 = x509.load_pem_x509_certificate(certificate, default_backend())
        certificate_reformatted = certificate_x509.public_bytes(serialization.Encoding.DER)
        acme_client.certificate_revocation(certificate_reformatted)

    # shutdown all servers -- over Shutdown server??
    shutdown_thread.join()
    os._exit(0)