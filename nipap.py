import pynipap
import configparser
import ipaddress
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
res = ipam.search('10.0.0.0/8')
db = {
    'children': {}
}

def is_subnet_of(a, b):
    try:
        # Always false if one is v4 and the other is v6.
        if a._version != b._version:
            raise TypeError(f"{a} and {b} are not of the same version")
        return (b.network_address <= a.network_address and
                b.broadcast_address >= a.broadcast_address)
    except AttributeError:
        raise TypeError(f"Unable to test subnet containment "f"between {a} and {b}")


def find_parent(prefix, tree, parent_candidate='', depth=0):
    network = ipaddress.ip_network(prefix.prefix)
    if prefix.indent == depth:
        tree['children'][prefix.prefix] = {
            'parent': parent_candidate,
            'prefix': prefix,
            'children': {}
        }
        return "%s -> %s" % (prefix.prefix, parent_candidate)
    for p in tree['children']:
        #print("Debug: %s" % p)
        parent_network = ipaddress.ip_network(p)
        if is_subnet_of(network, parent_network):
            return find_parent(prefix, tree['children'][p], p, depth+1)


for p in res:
    print(find_parent(p, db))
    # print(p.prefix, p.indent)
