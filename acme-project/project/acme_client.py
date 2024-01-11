"""

*** ACME client ***

    FUNCTIONALITY:
    - interact with ACME server (using ACMEv2 protocol)
    - request and obtain certificates:
        - using dns-01 and htp-01 challenge (fresh keys per run)
        - with wildcard domain names (non-existent domain names, e.g. *.example.com)
        - revoke certificates after they have been issued by the ACME server

        ****** VIDEO NOTES ******
        1. ACME client generates key pair and creates account with the ACME server (sign request with private key)
        2. ACME client requests a certificate for a domain name
        3. ACME server sends a challenge to the client: HTTP or DNS
        3.1 HTTP: ACME client responds to the challenge by serving a file on a webserver
        3.2 DNS: ACME client responds to the challenge by creating a DNS record
        4. Notifies ACME server that the challenge has been completed
        5. ACME server verifies the challenge by GET request to the webserver or by querying the DNS server
        6. client has proved ownership of domain name
        7. ACME client now: generates a new key pair, creates a CSR (using new key pair), sends CSR to ACME server (signed with account pk)
        8. ACME server verifies the CSR, issues a certificate, sends it to the client (client GET)
        
        """
import requests
import json
import base64       # binary fields in JSOn objects are base64url-encoded, JSON websignature, must strip trailing '='
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa




class AcmeClient:
    def __init__(self, directory_url):
        self.directory_url = directory_url
        self.trust_root = "pebble.minica.pem"

        # ----- URLs from Directory object (ACMEServer) -----
        self.new_nonce_url = None
        self.new_account_url = None
        self.new_order_url = None
        self.revoke_cert_url = None

        # ----- Other parameters -----
        self.ecc_key = None
        self.ecdsa_signing_alg = None
        self.anti_replay_nonce = None
        self.client_account_url = None      # [Page 36]: account URL is used as "kid" in JWS header
        self.client_headers = None
        self.client_jwk = None

        # ----- Startup client -----
        self.start_client()


    # ----- Helper functions -----
 
    def start_client(self):
        """Initialization of ACME client attributes"""
        self.get_directory()
        self.get_nonce()
        self.generate_key()
        self.set_signing_alg()
        self.create_jwk()
        self.create_account()

    
    def encode_b64url(self, url):
        """Encode a string in base64url format: use URL safe character set, strip trailing '='"""
        if type(url) == str:
            url = url.encode('utf-8')
        return base64.urlsafe_b64encode(url).decode('utf-8').rstrip('=')


    # ----- JWS object creation -----

    def create_jwk(self):
        """Create JSON Web Key (JWK) object: data strucutre that stores hashing key"""

        # explanation: [Page 5] of RFC 7517
        x_enc = self.encode_b64url(self.ecc_key.pointQ.x.to_bytes())
        y_enc = self.encode_b64url(self.ecc_key.pointQ.y.to_bytes())

        # using an Elliptic Curve key
        jwk = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': x_enc,
            'y': y_enc
        }

        self.client_jwk = jwk

        return jwk


    def create_jws_object(self, key_type, payload, url):
        """Encapsulate payload in a JSON Web Signature (JWS) object"""
        nonce = self.get_nonce()

        # different key types depend on the type of request made to the ACME server
        if key_type == "jwk":
            key = self.client_jwk
        elif key_type == "kid":
            key = self.client_account_url
        
        # create JWS header, TODO: encode header in base64url for final jws object
        header = {
            'alg': 'ES256',
            key_type: key,
            'nonce': nonce,
            'url': url
        }

        # enccode header and payload in base64url
        header_enc = self.encode_b64url(json.dumps(header))

        # treat empty payload case
        if payload == "":
            payload_enc = ""
            message_enc = str.encode("{}.".format(header_enc) , encoding='ascii')
        else:
            payload_enc = self.encode_b64url(json.dumps(payload))
            message_enc = str.encode("{}.{}".format(header_enc, payload_enc) , encoding='ascii')

        # digital signature over JWS protected header and JWS payload (RFC 7515)
        message_hash = SHA256.new(message_enc)
        ecdsa_signature = self.ecdsa_signing_alg.sign(message_hash)

        # Create JWS object
        jws_object = {}
        jws_object['protected'] = header_enc
        jws_object['payload'] = payload_enc
        jws_object['signature'] = self.encode_b64url(ecdsa_signature)

        return jws_object

    # ----- Key authorization string, for validation challenges  -----

    def create_key_auth_string(self, challenge_token):
        '''Concatenation of challenge token, ., and thumbprint of account key'''

        key_enc = str.encode(json.dumps(self.client_jwk, separators=(',', ':')), encoding="utf-8")
        key_hash = self.encode_b64url(SHA256.new(key_enc).digest())

        # concatenate challenge token and key hash
        auth_string = "{}.{}".format(challenge_token, key_hash)

        return auth_string




    # ----- CSR creation -----

    def create_csr(self, domains):
        """Create a CSR for a list of domains, using the ECC key generated by the client"""
        csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "twakonig-domains"),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        ).sign(csr_key, hashes.SHA256(), default_backend())

        # put into DER format
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        return csr_key, csr_der


    # ----- Outline of typical sequence of requests: [Page 22] of RFC 8555 -----
    # ------- Naming of methods: corresponds to requests to ACME server -------

    def get_directory(self):
        """Retrieve values from directory object to configure client"""

        # GET JSON directory object
        directory_object = requests.get(self.directory_url, verify=self.trust_root)

        # check status code of response
        if directory_object.status_code == requests.codes.ok:
            self.new_nonce_url = directory_object.json()['newNonce']
            self.new_account_url = directory_object.json()['newAccount']
            self.new_order_url = directory_object.json()['newOrder']
            self.revoke_cert_url = directory_object.json()['revokeCert']
        else:
            directory_object.raise_for_status()


    def get_nonce(self):
        """Get fresh nonce from ACME server, store in: self.anti_replay_nonce"""

        # GET request to get new nonce (instead of HEAD)
        new_nonce = requests.get(self.new_nonce_url, verify=self.trust_root)

        # check status code of response
        if new_nonce.status_code == requests.codes.ok:
            self.anti_replay_nonce = new_nonce.headers['Replay-Nonce']
        else:
            new_nonce.raise_for_status()


    def generate_key(self):
        """Generate a new ECC key, use P-256 curve"""
        key = ECC.generate(curve='P-256')
        self.ecc_key = key

    
    def set_signing_alg(self):
        """Set signing algorithm for JWS object"""
        signer = DSS.new(self.ecc_key, 'fips-186-3')
        self.ecdsa_signing_alg = signer


    def create_account(self):
        """Create a new account on the ACME server and set headers for future requests"""

        # parameters to create JWS object
        key_type = "jwk"
        payload = {'termsOfServiceAgreed': True}
        url = self.new_account_url

        # set client headers ONCE
        self.client_headers = {'User-Agent': 'twakonig-acme-client', 'Content-Type': 'application/jose+json'}
    
        # POST request to ACME server to create an account
        creation_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if creation_response.status_code == requests.codes.ok:
            # store account URL of account object (= "kid" in JWS header)
            self.client_account_url = creation_response.headers['Location']
            print("Account created at URL: ", self.client_account_url)
        else:
            creation_response.raise_for_status()

        
    def submit_certificate_order(self, domains):
        '''Order certificate for given domain/s. Returns list of authorization objects. '''
        # parameters to create JWS object
        key_type = "kid"
        payload = {'identifiers': [{'type': 'dns', 'value': d} for d in domains]}
        url = self.new_order_url

        # POST request to ACME server to apply for certificate issuance
        order_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if order_response.status_code == requests.codes.ok:
            # [Page 46], need to fulfill all authorization objects
            authorization_objects = order_response.json()['authorizations']
            order_url = order_response.headers['Location']
            finalize_url = order_response.json()['finalize']
        else:
            order_response.raise_for_status()

        return authorization_objects, order_url, finalize_url
    


    def fetch_challenges(self, authorization_url, cli_challenge_type):
        '''Fetch challenges from authorizations received after posting new order. Return url and token of challenge.'''
        # parameters to create JWS object - EMPTY PAYLOAD!!!
        key_type = "kid"
        payload = ""
        url = authorization_url     # from authorizations array in order response!

        # POST-as-GET to order's authorization urls
        fetch_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if fetch_response.status_code == requests.codes.ok:
            domain_name = fetch_response.json()['identifier']['value']
            challenges = fetch_response.json()['challenges']

            # filter for challenge type and find url and token ([page 54])
            for c in challenges: 
                if c['type'] == cli_challenge_type:
                    challenge_url = c['url']
                    challenge_token = c['token']
                    break
        else:
            fetch_response.raise_for_status()

        return challenge_url, challenge_token, domain_name


    def ready_for_challenge_validation(self, challenge_url):
        '''Client is ready for the challenge validation to be attempted. Send POST request to challenge URL'''
        # parameters to create JWS object
        key_type = "kid"
        payload = {}
        url = challenge_url     # from authorizations array in order response!
        
        # POST request to challenge URL
        start_val_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url),  verify=self.trust_root)

        # check status code of response
        if start_val_response.status_code == requests.codes.ok:
            status = start_val_response.json()['status']
        else:
            start_val_response.raise_for_status()

        return status


    def poll_for_status(self, resource_url):
        '''Poll for status by via POST request to resource URL'''
        # parameters to create JWS object
        key_type = "kid"
        payload = ""
        url = resource_url

        poll_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if poll_response.status_code == requests.codes.ok:
            status = poll_response.json()['status']
        else:
            poll_response.raise_for_status()

        return status


    def finalize_order(self, finalize_url, csr_der):
        '''Post CSR to finalize_url to finalize order, returns response including status and certificate?'''
        csr = self.encode_b64url(csr_der)      # TODO: need to encode HERE???

        # parameters to create JWS object
        key_type = "kid"
        payload = {'csr': csr}     
        url = finalize_url

        # POST request to finalize URL
        finalize_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if finalize_response.status_code == requests.codes.ok:
            print("Order finalized, CSR sent to server!")
        else:
            finalize_response.raise_for_status()


    # quickfix
    def get_certificate_url(self, url):
        '''Get certificate URL from order object'''
        # parameters to create JWS object
        key_type = "kid"
        payload = ""

        poll_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if poll_response.status_code == requests.codes.ok:
            cert_url = poll_response.json()['certificate']
        else:
            poll_response.raise_for_status()

        return cert_url


    def download_certificate(self, certificate_url):
        '''Download certificate from certificate URL'''

        # parameters to create JWS object
        key_type = "kid"
        payload = ""
        url = certificate_url

        # POST-as-GET request to certificate URL
        download_response = requests.post(url, headers=self.client_headers, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if download_response.status_code == 200:
            certificate = download_response.content
        
        return certificate
      

    def certificate_revocation(self, certificate):
        '''Revoke certificate, does not return anything'''

        # parameters to create JWS object
        key_type = "kid"
        payload = {'certificate': self.encode_b64url(certificate)}
        url = self.revoke_cert_url

        # POST request to ACME server to revoke certificate
        response = requests.post(url, json=self.create_jws_object(key_type, payload, url), verify=self.trust_root)

        # check status code of response
        if response.status_code == requests.codes.ok:
            print("Certificate successfully revoked.")
        else:
            response.raise_for_status()



    


    





