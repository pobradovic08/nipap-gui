"""
nipap-gui
TkInter GUI for nipap (https://github.com/SpriteLink/NIPAP)

Copyright (C) 2018  Pavle Obradovic <pobradovic08>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import pynipap
import ipaddress
import threading
import re

from classess import IpamCommon
from pynipap import VRF, Pool, Prefix


class IpamBackend:

    def __init__(self, main_queue, cfg):
        self.queue = main_queue
        self.lock = threading.Lock()
        self.host = ""

        # Accessed from GUI
        self.vrfs = {}
        self.pools = {}
        self.vrf_labels = {}

        # Search parameters
        self.search_string = ''
        self.search_pattern = None
        self.search_vlan = None

        self._init_db()
        self.load_config(cfg)

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

        try:
            vrf_list = VRF.list()
        except Exception as e:
            self.lock.release()
            raise e

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
        return True if self.vrfs else False

    def get_pools(self):
        self.lock.acquire()
        try:
            self.pools = Pool.list()
        except Exception as e:
            self.lock.release()
            raise e
        self.lock.release()


    def search(self, search_string='', vrf_id=None, filters=None):
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

        # Build VRF query based on `vrf_id` to be used as `extra_query` param
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

        try:
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
        except Exception as e:
            self.lock.release()
            raise e

        self.lock.release()

    @staticmethod
    def fill_blanks(prefix_entry):
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
        all_prefixes = IpamCommon.supernet_fill_gaps(supernet, prefixes)

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
        filtered_array = list(filter(lambda i: i in p_types, type_list))

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
                if IpamCommon.is_subnet_of(network, parent_network):
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

    def save_prefix(self, prefix):
        """
        Save already built prefix
        :param prefix: pynipap.Prefix
        :return: status? prolly nothing
        """
        self.lock.acquire()
        try:
            status = prefix.save()
        except Exception as e:
            self.lock.release()
            raise e
        else:
            self.lock.release()
            return status

    def delete_prefix(self, prefix, vrf_id, recursive=False):
        """
        Delete prefix
        :param recursive:
        :param prefix: prefix (string)
        :param vrf_id: vrf_id
        :return:
        """
        self.lock.acquire()
        try:
            # Search for prefixes matching prefix & vrf_id

            query = {
                'operator': 'and',
                'val1': {
                    'operator': 'equals',
                    'val1': 'prefix',
                    'val2': prefix,
                },
                'val2': {
                    'operator': 'equals',
                    'val1': 'vrf_id',
                    'val2': vrf_id
                }
            }

            # prefixes = Prefix.smart_search(prefix, extra_query= {
            #     "operator": "equals",
            #     "val1": "vrf_id",
            #     "val2": vrf_id
            # })['result']
            prefixes = Prefix.search(query)['result']

            print(prefixes)

            # If only one prefix is found, delete it
            if len(prefixes) == 1:
                p = prefixes.pop(0)
                print(p.remove(recursive))

            # Check if still there
            prefixes_left = len(Prefix.search(query)['result'])
            self.lock.release()
            return prefixes_left == 0

        except Exception as e:
            self.lock.release()
            raise e
