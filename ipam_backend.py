import pynipap
import configparser
import ipaddress
import threading
import queue
from pynipap import VRF, Pool, Prefix


class IpamBackend:

    def __init__(self, main_queue):
        self.queue = main_queue
        self.lock = threading.Lock()
        config = configparser.ConfigParser()
        config.read('config.ini')
        nipap_config = config['nipap']
        self.host = ""
        self.vrfs = {}
        self.vrf_labels = {}
        self._init_db()
        if 'host' in nipap_config:
            self.host = nipap_config['host']
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
            self.get_vrfs()

    def _init_db(self):
        """
        Initialize `db` dictionary
        :return:
        """
        self.db = {
            'children': {}
        }

    def get_vrfs(self):
        self.lock.acquire()
        vrf_list = VRF.list()
        for vrf in vrf_list:
            self.vrfs[vrf.id] = {
                'label': "%s [%s]" % (vrf.name, vrf.rt),
                'vrf': vrf
            }
            label = "VRF %s [%s]" % (vrf.name, vrf.rt) if vrf.rt else "VRF %s" % vrf.name
            self.vrf_labels[label] = str(vrf.id)
        self.lock.release()

    def search(self, search_string='', vrf_id=None):
        self.lock.acquire()
        # Clear current dictionary
        self._init_db()

        # Build VRF query based on `vrf_id` to be used as `extra_query` param
        vrf_q = None if not vrf_id else {
            'operator': 'equals',
            'val1': 'vrf_id',
            'val2': vrf_id
        }

        #Debug
        #print(vrf_q)

        search_result = Prefix.smart_search(search_string, search_options={
            'parents_depth': -1,
            'children_depth': -1,
            'max_result': 0
        }, extra_query=vrf_q)['result']

        for prefix in search_result:
            #print("Prefix %s" % prefix.prefix)
            self.find_parent(prefix, self.db)
        self.lock.release()

    def find_parent(self, prefix, tree, parent_candidate='', depth=0):
        network = ipaddress.ip_network(prefix.prefix)
        if prefix.indent == depth:
            tree['children'][prefix.prefix] = {
                'parent': parent_candidate,
                'prefix': prefix,
                'children': {}
            }
            #print("%s -> %s" % (prefix.prefix, parent_candidate))
            return "%s -> %s" % (prefix.prefix, parent_candidate)
        for p in tree['children']:
            parent_network = ipaddress.ip_network(p)
            try:
                if self.is_subnet_of(network, parent_network):
                    return self.find_parent(prefix, tree['children'][p], p, depth + 1)
            except TypeError:
                continue

    @staticmethod
    def is_subnet_of(a, b):
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError(f"{a} and {b} are not of the same version")
            return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
        except AttributeError:
            raise TypeError(f"Unable to test subnet containment "f"between {a} and {b}")