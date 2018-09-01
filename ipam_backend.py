import pynipap
import ipaddress
import threading
import re
from pynipap import VRF, Pool, Prefix


class IpamBackend:

    def __init__(self, main_queue, cfg):
        self.queue = main_queue
        self.lock = threading.Lock()
        self.host = ""

        # Accessed from GUI
        self.vrfs = {}
        self.vrf_labels = {}

        # Search parameters
        self.search_string = ''
        self.search_pattern = None
        self.search_vlan = None

        self._init_db()
        self.load_config(cfg)
        # TODO: Maybe move this to separate method
        self.get_vrfs()

    def load_config(self, nipap_config):
        """
        Fetch connection parameters from provided dict
        and build xmlrpc_url to connect to Nipap API
        :param nipap_config:
        :return:
        """

        # Required parameters in config file
        required = ['host', 'username', 'password', 'port']
        # Check if all params are present in config and build URL
        if all([param in nipap_config for param in required]):
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
        else:
            raise Exception("No nipap host defined in config file")

    def _init_db(self):
        """
        Initialize `db` dictionary
        :return:
        """
        self.db = {
            'children': {}
        }

    def get_vrfs(self):
        """
        Get the list of VRFs from nipap
        self.vrfs = {
            1: {
                "label": "global [65001:1234]",
                "vrf": nipap.VRF
            },
            ....
        }
        self.vrf_labels = {
            "global [65001:1234]": 1,
            "default": 2,
            ...
        }
        :return:
        """
        self.lock.acquire()
        vrf_list = VRF.list()

        # Populate `self.vrfs` and `self.vrf_labels`
        for vrf in vrf_list:
            self.vrfs[vrf.id] = {
                'label': "%s [%s]" % (vrf.name, vrf.rt),
                'vrf': vrf
            }
            # If there's no RT (such in global), don't display brackets
            label = "VRF %s [%s]" % (vrf.name, vrf.rt) if vrf.rt else "VRF %s" % vrf.name
            self.vrf_labels[label] = str(vrf.id)
        self.lock.release()

    def search(self, search_string='', vrf_id=None, filters = None):
        """
        Fetch prefixes matching search string

        :param search_string:   Search string provided by GUI
        :param vrf_id:          VRF ID provided by GUI
        :param filters:         Filters (Prefix type) provided by GUI
        :return:                None
        """
        self.lock.acquire()
        # Clear current dictionary
        self._init_db()

        # Compile search string
        self.search_string = search_string
        self.search_pattern = re.compile(self.search_string, re.IGNORECASE)

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

        # For each prefix in search results find a parent prefix
        # This is (unfortunately) based on the fact that prefix
        # list from search IS ordered (parent exists before children)
        for prefix in search_result:
            self.find_parent(prefix, self.db)

        self.lock.release()

    def fill_blanks(self, prefix_entry):
        """
        Finds missing children for a prefix and creates dummy objects
        that will be shown in GUI as free prefixes

        :param prefix_entry:    Target prefix
        :return:                None
        """

        # If 'children' dictionary is empty
        if 'children' not in prefix_entry or not prefix_entry['children']:
            return

        # Get supernet and existing children prefixes
        supernet = prefix_entry['prefix'].prefix
        prefixes = list(prefix_entry['children'].keys())

        # Calculate all prefixes that should be subnets of supernet
        # with constraints posed by existing prefixes
        all_prefixes = IpamBackend.supernet_fill_gaps(supernet, prefixes)

        # For every prefix that is not in the list of childrens
        # make a fake entry with `None` as a `prefix` attribute
        # This will be later shown as a free prefix in GUI
        for p in all_prefixes:
            if p not in prefixes:
                prefix_entry['children'][p] = {
                    'parent': prefix_entry['parent'],
                    'prefix': None,
                    'selected': False,
                    'children': {}
                }

    def status_filter_build(self, type_list, current_query=None):
        """
        Recursively build a query dictionary used as a `extra_query` parameter
        of nipap's smart_search function. Types that exist in `type_list` will
        be shown (not filtered). This would be equivalent to `status=={type}`
        
        :param type_list:       List of remaining types to add to query dict
        :param current_query:   Current query dict
        :return:                Query dict
        """

        # Known prefix types
        p_types = ['reserved', 'assigned', 'quarantine']
        # Remove keys not matching known prefix types in `type_list` to avoid backend errors
        filtered_array = list(filter(lambda item: item in p_types, type_list))

        # If all types are shown return
        if len(filtered_array) == len(p_types):
           return None

        # If there's no types to add, return query
        if not filtered_array:
            return current_query

        # Pop first list item and make a temp dict
        item = filtered_array.pop(0)
        tmp_query = {
            'operator': 'equals',
            'val1': 'status',
            'val2': item
        }

        # If the current query is empty use temp dict
        if not current_query:
            current_query = tmp_query
        # If we have current query, OR the temp one with it
        else:
            current_query = {
                'operator': 'or',
                'val1': current_query,
                'val2': tmp_query
            }

        # Call itself with new `filtered_array` (without first element)
        # and newly built current query
        return self.status_filter_build(filtered_array, current_query)

    def find_parent(self, prefix, tree, parent_candidate='', depth=0):
        """
        Recursively build a structured dictionary from nipap prefixes
        Example dictionary looks like:

        self.db = {
            "parent": "",
            "prefix": ipaddress.IPv[46]Network object,
            "selected": False,
            "children": {
                "10.0.0.0/24": {
                    "parent": "10.0.0.0/23",
                    "prefix": ipaddress.IPv[46]Network object,
                    "selected": False,
                    'children': {
                        ...
                    }
                }
            }
        }

        `parent` specifies the parent prefix (or none if on top level - indent 0)
        `prefix` is a IPv4Network or IPv6Network ipaddress object
        `selected` is set depending on the search term matching the prefix
        `children` is a dictionary of children of the same structure

        :param prefix:              Current prefixt to nest
        :param tree:                Current tree part
        :param parent_candidate:    Parent prefix candidate
        :param depth:               Current nipap tree depth
        :return:                    Parent prefix
        """

        network = ipaddress.ip_network(prefix.prefix)

        # If the prefix indent from database matches the depth in our tree
        # there's no need to go any further; insert prefix to children's of
        # the tree part we're examining (matching parent candidate) and
        # return parent candidate
        if prefix.indent == depth:
            tree['children'][prefix.prefix] = {
                'parent': parent_candidate,
                'prefix': prefix,
                'selected': self.search_matches_prefix(prefix),
                'children': {}
            }
            return parent_candidate

        # If depth not reached go through parent candidate children and
        # find a one that is a supernet for our prefix, then call itself
        # with new parent candidate, corresponding part of the tree and
        # new depth
        for p in tree['children']:
            parent_network = ipaddress.ip_network(p)
            try:
                if self.is_subnet_of(network, parent_network):
                    return self.find_parent(prefix, tree['children'][p], p, depth + 1)
            except TypeError:
                # If we try to match IPv4 against IPv6 and fail, just skip it
                continue

    def search_matches_prefix(self, prefix):
        """
        Returns True if any of defined prefix attributes matches search criteria
        :param prefix: pynipap Prefix object
        :return:
        """

        # If the search string is empty or none don't mark any prefixes
        if not self.search_string:
            return False

        # List of values to check
        match_against = [
            prefix.prefix,
            prefix.description,
            prefix.comment
        ]

        # Search for `pattern` in list of values
        for value in match_against:
            if value and re.search(self.search_pattern, value):
                return True

    @staticmethod
    def is_subnet_of(a, b):
        """
        Copied from Python 3.7 code
        :param a:
        :param b:
        :return:
        """
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError(f"{a} and {b} are not of the same version")
            return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
        except AttributeError:
            raise TypeError(f"Unable to test subnet containment "f"between {a} and {b}")

    @staticmethod
    def find_gaps_between_prefixes(from_prefix, to_prefix, missing_list=None):
        """
        Recursively find prefixes to fill the gap between two subnets

        :param from_prefix:     IPv4Network or string of start prefix
        :param to_prefix:       IPv4Network or string of end prefix
        :param missing_list:    List of missing prefixes found
        :return:                array of strings representing IP prefix
        """

        # If these are not a IPv4Network or IPv6Network objects make them be
        from_prefix = IpamBackend.str_to_prefix(from_prefix)
        to_prefix = IpamBackend.str_to_prefix(to_prefix)

        # Initialize empty list
        if missing_list is None:
            missing_list = []

        cidr = -1
        next_ip = from_prefix.broadcast_address + 1

        # If next IP is higher than right border prefix
        # It's a mistake, return empty list (or raise exception?)
        if next_ip > to_prefix.network_address:
            return []

        # If next IP is the same as right border prefix, there's no more gaps
        if next_ip == to_prefix.network_address:
            return missing_list

        # Starting CIDR for IPv4 or IPv6
        if isinstance(from_prefix, ipaddress.IPv4Network):
            cidr_start = 32
        elif isinstance(from_prefix, ipaddress.IPv6Network):
            cidr_start = 64
        else:
            raise ValueError("Prefix not v4 nor v6")

        # Find the shortest prefix match that doesn't overlap with `first_known_prefix`
        # We're looking for the first missing prefix (with network address of `next_ip`)
        # TODO: Extract to separate method
        for cidr_candidate in range(cidr_start, 0, -1):
            try:
                # Build prefix candidate
                prefix_candidate = ipaddress.ip_network("%s/%d" % (next_ip, cidr_candidate))
                if to_prefix.overlaps(prefix_candidate):
                    raise ValueError()
            except ValueError:
                # If the overlap happened, stop at previous CIDR value (+1)
                cidr = cidr_candidate + 1
                break

        # Finding a prefix failed
        if cidr == -1:
            return False

        # Construct a prefix with calculated CIDR and append it to missing prefix list
        missing_prefix = ipaddress.ip_network("%s/%d" % (next_ip, cidr))
        missing_list.append(str(missing_prefix))

        # Recursively call the same the same prefix but set the first prefix to the one just found
        return IpamBackend.find_gaps_between_prefixes(missing_prefix, to_prefix, missing_list)

    @staticmethod
    def _find_first_prefix(supernet, first_known_prefix):
        """
        Find first prefix in the `supernet` honoring the constraint posed by `first_known_prefix`
        Real first prefix could be the same as `first_known_prefix`

        :param supernet:            Supernet for which to find first prefix
        :param first_known_prefix:   Lirst known prefix in the supernet
        :return:
        """

        # If these are not a IPv4Network or IPv6Network objects make them be
        supernet = IpamBackend.str_to_prefix(supernet)
        first_known_prefix = IpamBackend.str_to_prefix(first_known_prefix)

        # Find the first IP for supernet
        start_ip = supernet.network_address
        # If first IP's of supernet and `first_known_prefix` are the same, there's no gap
        if start_ip == first_known_prefix.network_address:
            return None

        # Check if `first_known_prefix` really does belong to `supernet`
        if IpamBackend.is_subnet_of(first_known_prefix, supernet):
            cidr = -1

            # Starting CIDR for IPv4 or IPv6
            if isinstance(supernet, ipaddress.IPv4Network):
                cidr_start = 32
            elif isinstance(supernet, ipaddress.IPv6Network):
                cidr_start = 64
            else:
                raise ValueError("Prefix not v4 nor v6")

            # Find the shortest prefix match that doesn't overlap with `first_known_prefix`
            for cidr_candidate in range(cidr_start, 0, -1):
                try:
                    # Build prefix candidate
                    prefix_candidate = ipaddress.ip_network("%s/%d" % (start_ip, cidr_candidate))
                    if first_known_prefix.overlaps(prefix_candidate):
                        raise ValueError()
                except ValueError:
                    # If the overlap happened, stop at previous CIDR value (+1)
                    cidr = cidr_candidate + 1
                    break

            # Finding a prefix failed
            if cidr == -1:
                return None

            # Construct a prefix with calculated CIDR and return it
            missing_prefix = ipaddress.ip_network("%s/%d" % (start_ip, cidr))
            return str(missing_prefix)


    @staticmethod
    def _find_last_prefix(supernet, last_known_prefix):
        """
        Find last prefix in the `supernet` honoring the constraint posed by `last_known_prefix`
        Real ast prefix could be the same as `last_known_prefix`

        :param supernet:            Supernet for which to find last prefix
        :param last_known_prefix:   Last known prefix in the supernet
        :return:
        """

        # If the supernet is not a IPv4Network or IPv6Network object make it one
        supernet = IpamBackend.str_to_prefix(supernet)

        # If the `last_known_prefix` is not a IPv4Network or IPv6Network object make it one
        last_known_prefix = IpamBackend.str_to_prefix(last_known_prefix)

        # Find last IP for supernet
        end_ip = supernet.broadcast_address
        # If last IP's of supernet and `last_known_prefix` are the same, there's no gap
        if end_ip == last_known_prefix.broadcast_address:
            return None
        # Check if `last_known_prefix` really does belong to `supernet`
        if IpamBackend.is_subnet_of(last_known_prefix, supernet):
            cidr = -1

            # Starting CIDR for IPv4 or IPv6
            if isinstance(supernet, ipaddress.IPv4Network):
                cidr_start = 32
            elif isinstance(supernet, ipaddress.IPv6Network):
                cidr_start = 64
            else:
                raise ValueError("Prefix not v4 nor v6")

            # Find the shortest prefix match that doesn't overlap with `last_known_prefix`
            for cidr_candidate in range(cidr_start, 0, -1):
                try:
                    # Build prefix candidate, disable strict because we're using broadcast address as a base
                    prefix_candidate = ipaddress.ip_network("%s/%d" % (end_ip, cidr_candidate), strict=False)
                    if last_known_prefix.overlaps(prefix_candidate):
                        raise ValueError()
                except ValueError:
                    # If the overlap happened, stop at previous CIDR value (+1)
                    cidr = cidr_candidate + 1
                    break

            # Finding a prefix failed
            if cidr == -1:
                return None

            # Construct a prefix with calculated CIDR and return it
            missing_prefix = ipaddress.ip_network("%s/%d" % (end_ip, cidr), strict=False)
            return str(missing_prefix)


    @staticmethod
    def _find_missing_between_prefixes(prefix_list, missing_list=None):
        """
        Recursively find missing prefixes from `prefix_list` and populate `missing_list`
        Method is basically finding missing prefixes between first two elements of `prefix_list`
        and then calling itself with a shortened list (for a first prefix)

        :param prefix_list:     List of existing prefixes (original and missing that are found)
        :param missing_list:    Current list of missing prefixes
        :return:                List of missing prefixes
        """

        # Initialize the list
        if missing_list is None:
            missing_list = []

        # If we have only one prefix left in the list there are no more gaps
        if len(prefix_list) < 2:
            return missing_list

        # Sort prefix list
        prefix_list = sorted(prefix_list, key=lambda prefix: ipaddress.ip_network(prefix))

        # Find missing prefixes between first two prefixes and add them to prefix list and missing list
        gaps = IpamBackend.find_gaps_between_prefixes(prefix_list[0], prefix_list[1])
        if gaps:
            prefix_list.extend(gaps)
            missing_list.extend(gaps)

        # Recursively find the same for the next of the list
        return IpamBackend._find_missing_between_prefixes(prefix_list[1:], missing_list)


    @staticmethod
    def supernet_fill_gaps(supernet, prefix_list):
        """
        Calculates missing subnets for a prefix `supernet` and a list of current subnets `prefix_list`
        and returns a complete list of subnets.

        :param supernet:    Supernet which to fill
        :param prefix_list: List of subnets present in the supernet
        :return:
        """

        # If the prefix list is empty, the subnet is the same as the supernet
        if not prefix_list:
            return None

        # If the supernet is not a IPv4Network or IPv6Network object make it one
        supernet = IpamBackend.str_to_prefix(supernet)

        # Sort current list of prefixes
        prefix_list = sorted(prefix_list, key=lambda prefix: ipaddress.ip_network(prefix))

        # Find the first gap (first prefix) and add it to the beginning of `prefix_list`
        first_gap = IpamBackend._find_first_prefix(supernet, prefix_list[0])
        if first_gap:
            prefix_list.insert(0, first_gap)

        # Find the last gap (last prefix) and add it to the end of `prefix_list`
        last_gap = IpamBackend._find_last_prefix(supernet, prefix_list[-1])
        if last_gap:
            prefix_list.append(last_gap)

        # Now that we have border prefixes we can fill the gaps between
        missing = IpamBackend._find_missing_between_prefixes(prefix_list)
        # Merge missing prefixes
        prefix_list.extend(missing)
        # Sort them
        return sorted(prefix_list, key=lambda prefix: ipaddress.ip_network(prefix))


    @staticmethod
    def str_to_prefix(prefix):
        """
        Check if prefix is not an object (ipaddress.IPv4Network/ipaddress.IPv6Network) and make it

        :param prefix:  string or ipaddress.IPv4Network/ipaddress.IPv6Network
        :return:        ipaddress.IPv4Network or ipaddress.IPv6Network
        """
        if not isinstance(prefix, ipaddress.IPv4Network) and not isinstance(prefix, ipaddress.IPv6Network):
            return ipaddress.ip_network(prefix)
        else:
            return prefix