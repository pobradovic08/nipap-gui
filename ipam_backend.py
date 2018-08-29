import pynipap
import configparser
import ipaddress
import threading
import queue
from pynipap import VRF, Pool, Prefix


class IpamBackend:

    def __init__(self, main_queue, cfg):
        self.queue = main_queue
        self.lock = threading.Lock()
        # TODO: clean unused
        config = configparser.ConfigParser()
        config.read('config.ini')
        #nipap_config = config['nipap']
        nipap_config = cfg
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

    def search(self, search_string='', vrf_id=None, filters = None):
        self.lock.acquire()
        # Clear current dictionary
        self._init_db()

        #Build VRF query based on `vrf_id` to be used as `extra_query` param
        vrf_q = None if not vrf_id else {
            'operator': 'equals',
            'val1': 'vrf_id',
            'val2': vrf_id
        }

        # Build status filters
        filter_q = self.status_filter_build(filters)

        # Combine vrf_q and filter_q
        if vrf_q:
            extra_q = vrf_q if not filter_q else {
                'operator': 'and',
                'val1': vrf_q,
                'val2': filter_q
            }
        else:
            extra_q = filter_q

        search_result = Prefix.smart_search(search_string, search_options={
            'parents_depth': -1,
            'children_depth': -1,
            'max_result': 0
        }, extra_query=extra_q)['result']

        for prefix in search_result:
            #print("Prefix %s" % prefix.prefix)
            self.find_parent(prefix, self.db)
        self.lock.release()

    def status_filter_build(self, type_array, query=None):
        filtered_array = list(filter(lambda item: item in ('reserved', 'assigned', 'quarantine'), type_array))
        if len(filtered_array) == 3:
           return None
        if not filtered_array:
            return query

        item = filtered_array.pop(0)

        tmp_query = {
            'operator': 'equals',
            'val1': 'status',
            'val2': item
        }

        if not query:
            query = tmp_query
        else:
            query = {
                'operator': 'or',
                'val1': query,
                'val2': tmp_query
            }

        return self.status_filter_build(filtered_array, query)

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

    @staticmethod
    def prefix_find_gaps(from_prefix, to_prefix, missing_list=None):
        """
        Recursively find prefixes to fill the gap between two subnets

        :param from_prefix: IPv4Network
        :param to_prefix: IPv4Network
        :param missing_list:
        :return:
        """

        if missing_list is None:
            missing_list = []
        cidr = -1
        next_ip = from_prefix.broadcast_address + 1
        if next_ip > to_prefix.network_address:
            print("From higher than to.")
            return []
        if next_ip == to_prefix.network_address:
            return missing_list

        for cidr_candidate in range(32, 0, -1):
            try:
                prefix_candidate = ipaddress.IPv4Network("%s/%d" % (next_ip, cidr_candidate))
                if to_prefix.overlaps(prefix_candidate):
                    raise ValueError()
            except ValueError:
                cidr = cidr_candidate + 1
                break

        if cidr == -1:
            return False
        missing_prefix = ipaddress.IPv4Network("%s/%d" % (next_ip, cidr))
        print("Missing: %s" % missing_prefix)
        missing_list.append(missing_prefix)

        return IpamBackend.prefix_find_gaps(missing_prefix, to_prefix, missing_list)