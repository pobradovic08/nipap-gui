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

import ipaddress

class IpamCommon:

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
                raise TypeError("Subnets are not of the same version")
            return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
        except AttributeError:
            raise TypeError("Unable to test subnet containment between subnets")

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
        from_prefix = IpamCommon.str_to_prefix(from_prefix)
        to_prefix = IpamCommon.str_to_prefix(to_prefix)

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
        return IpamCommon.find_gaps_between_prefixes(missing_prefix, to_prefix, missing_list)

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
        supernet = IpamCommon.str_to_prefix(supernet)
        first_known_prefix = IpamCommon.str_to_prefix(first_known_prefix)

        # Find the first IP for supernet
        start_ip = supernet.network_address
        # If first IP's of supernet and `first_known_prefix` are the same, there's no gap
        if start_ip == first_known_prefix.network_address:
            return None

        # Check if `first_known_prefix` really does belong to `supernet`
        if IpamCommon.is_subnet_of(first_known_prefix, supernet):
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
        supernet = IpamCommon.str_to_prefix(supernet)

        # If the `last_known_prefix` is not a IPv4Network or IPv6Network object make it one
        last_known_prefix = IpamCommon.str_to_prefix(last_known_prefix)

        # Find last IP for supernet
        end_ip = supernet.broadcast_address
        # If last IP's of supernet and `last_known_prefix` are the same, there's no gap
        if end_ip == last_known_prefix.broadcast_address:
            return None
        # Check if `last_known_prefix` really does belong to `supernet`
        if IpamCommon.is_subnet_of(last_known_prefix, supernet):
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
        gaps = IpamCommon.find_gaps_between_prefixes(prefix_list[0], prefix_list[1])
        if gaps:
            prefix_list.extend(gaps)
            missing_list.extend(gaps)

        # Recursively find the same for the next of the list
        return IpamCommon._find_missing_between_prefixes(prefix_list[1:], missing_list)


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
        supernet = IpamCommon.str_to_prefix(supernet)

        # Sort current list of prefixes
        prefix_list = sorted(prefix_list, key=lambda prefix: ipaddress.ip_network(prefix))

        # Find the first gap (first prefix) and add it to the beginning of `prefix_list`
        first_gap = IpamCommon._find_first_prefix(supernet, prefix_list[0])
        if first_gap:
            prefix_list.insert(0, first_gap)

        # Find the last gap (last prefix) and add it to the end of `prefix_list`
        last_gap = IpamCommon._find_last_prefix(supernet, prefix_list[-1])
        if last_gap:
            prefix_list.append(last_gap)

        # Now that we have border prefixes we can fill the gaps between
        missing = IpamCommon._find_missing_between_prefixes(prefix_list)
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
