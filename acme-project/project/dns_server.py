from dnslib.dns import RR, QTYPE, A, TXT
from dnslib.server import DNSServer, DNSLogger, BaseResolver

"""

*** DNS server ***

    FUNCTIONALITY:
    - provide a DNS server that can be used to resolve domain names (DNS queries, dns01 challenge) of the ACME server
    - runs on UDP port 10053

"""

# define class for DNS server
class DnsServer(BaseResolver):
        def __init__(self, record):
            # set record to be returned by DNS server
            self.record = record

            # TXT challenge variables
            self.txt_domain = None
            self.txt_key = None

    
        # resolve DNS query
        def resolve(self, request):
            # get query name and type
            qname = request.q.qname
            qtype = request.q.qtype
    
            # create response object
            reply = request.reply()
    
            # check if query type is A (IPv4 address) or TXT (text) (from ACME challenge)
            if qtype == QTYPE.A:
                reply.add_answer(RR(qname, qtype, rdata=A(self.record), ttl=300))
            elif qtype == QTYPE.TXT:
                reply.add_answer(RR(self.txt_domain, qtype, rdata=TXT(self.txt_key), ttl=300))

            return reply

        # for ACME Server challange
        def new_txt_challenge(self, domain, auth_string):
            # set challenge domain and data
            self.txt_domain = domain
            self.txt_key = auth_string


        def start_server(self):
            # start DNS server
            dns_logger = DNSLogger(prefix=False)
            dns_server = DNSServer(self, port=10053, address=self.record, logger=dns_logger)
            dns_server.start_thread()

