import pynipap
import configparser
from pynipap import VRF, Pool, Prefix


class IpamBackend:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        nipap_config = config['nipap']
        if 'host' in nipap_config:
            nipap_url = "http://%s:%s@%s:%d/XMLRPC" % (
                nipap_config['username'],
                nipap_config['password'],
                nipap_config['host'],
                int(nipap_config['port']),
            )
            pynipap.xmlrpc_uri = nipap_url
            pynipap.AuthOptions({
                'authoritative_source': 'nipap-gui'
            })

    def search(self, search_string):
        search_result = Prefix.smart_search(search_string, search_options={'parents_depth': -1})
        return search_result['result']

ipam = IpamBackend()
res = ipam.search('10.4.0.1/32')
for p in res:
    print(p.prefix, p.indent)