#!/usr/bin/env python3

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

import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as mbox
import ipaddress
import os
import threading
import queue
import configparser

from classess import IpamBackend
from classess import IpamCommon


class GuiThread:

    def __init__(self):
        app = NipapGui()
        app.master.title('NIPAP GUI')
        app.mainloop()


class NipapGui(ttk.Frame):

    def __init__(self, master=None):

        self.resources_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'resources'))

        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.prefixes = {}
        self.prefixes_v4 = {}
        self.prefixes_v6 = {}
        self.vrf_list = {}

        self.ipam_search_thread = None
        self.tree_v4 = None
        self.tree_v6 = None
        self.error = {}

        config = configparser.ConfigParser()
        config.read('config.ini')
        self.nipap_config = config['nipap']

        ttk.Frame.__init__(self, master, cursor='left_ptr', padding=10)
        top = self.winfo_toplevel()
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        # top.geometry('1024x768')
        # top.attributes('-fullscreen', True)
        top.iconbitmap(os.path.join(self.resources_path, 'nipap-gui.ico'))
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.grid(sticky=tk.N + tk.S + tk.E + tk.W)

        self.define_icons()
        style = ttk.Style()
        style.configure('Nipap.Treeview', font=('TkDefaultFont', 8, 'normal'))

        # Can't call before creating root window
        self.status = tk.StringVar()
        self.loading_string = tk.StringVar()
        self.search_string = tk.StringVar()
        self.current_vrf = tk.StringVar()
        self.filter_reserved = tk.IntVar(value=1)
        self.filter_assigned = tk.IntVar(value=1)
        self.filter_quarantine = tk.IntVar(value=1)

        self.bind('<<nipap_connected>>', self.connected)
        self.bind('<<nipap_refresh>>', self.refresh)
        self.bind('<<nipap_error>>', self.handle_error)

        self.connect_to_server()
        self.display_loading()

    def connect_to_server(self):
        # Spawn a thread for nipap initial connect
        self.ipam_connect_thread = threading.Thread(target=self.thread_ipam_connect)
        self.ipam_connect_thread.start()

    def connected(self, e):
        self.read_queue()
        self.loading.destroy()
        self.create_layout()
        self.run_search()

    def run_search(self, e=None):
        # If thread is already running wait for it
        if self.ipam_search_thread and self.ipam_search_thread.isAlive():
            print("Search already running")
            return

        self.ipam_search_thread = threading.Thread(target=self.thread_ipam_search)
        self.ipam_search_thread.start()

    def display_loading(self):
        self.loading = ttk.Frame(self)
        self.loading.grid(row=0, column=0)

        self.loading_string.set("Connecting to %s ..." % self.nipap_config['host'])
        self.loading_label = ttk.Label(self.loading, textvariable=self.loading_string)
        self.loading_label.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E + tk.W)
        self.pb = ttk.Progressbar(self.loading, mode='indeterminate')
        self.pb.start()
        self.pb.grid(row=1, column=0, sticky=tk.N + tk.S + tk.E + tk.W)

    def read_queue(self):
        while self.queue.qsize():
            try:
                msg = self.queue.get()
                self.lock.acquire()
                if msg['type'] == 'vrfs':
                    self.vrf_list = msg['data']
                elif msg['type'] == 'prefixes':
                    self.prefixes = msg['data']
                elif msg['type'] == 'error':
                    self.error['msg'] = msg['data']
                    self.error['callback'] = msg['callback']
                self.lock.release()
                # print(msg)
            except queue.Empty:
                pass

    def thread_ipam_connect(self):
        try:
            try:
                self.ipam = IpamBackend(self.queue, self.nipap_config)
            except Exception as e:
                self.event_generate('<<nipap_error>>', when='tail')
                self.queue.put({
                    'type': 'error',
                    'data': e,
                    'callback': self.connect_to_server,
                    'status': 'error'
                })
                return
            self.event_generate('<<nipap_connected>>', when='tail')
            self.queue.put({
                'type': 'vrfs',
                'data': self.ipam.vrf_labels,
                'status': 'ok'
            })
        except tk.TclError:
            return

    def thread_ipam_search(self):
        self.status.set("Searching %s for '%s'..." % (self.current_vrf.get(), self.search_string.get()))
        # Lookup selected vrf id in vrf_list dict
        vrf_id = self.vrf_list.get(self.current_vrf.get())

        # Create status filters
        filters = []
        if self.filter_reserved.get():
            filters.append('reserved')
        if self.filter_assigned.get():
            filters.append('assigned')
        if self.filter_quarantine.get():
            filters.append('quarantine')

        try:
            self.ipam.search(self.search_string.get(), vrf_id, filters)
        except Exception as e:
            self.event_generate('<<nipap_error>>', when='tail')
            self.queue.put({
                'type': 'error',
                'data': e,
                'callback': self.run_search,
                'status': 'error'
            })
            return
        try:
            self.status.set("Done.")
            self.event_generate('<<nipap_refresh>>', when='tail')
            self.queue.put({
                'type': 'prefixes',
                'data': self.ipam.db,
                'status': 'ok'
            })
        except tk.TclError as e:
            print(e)
            return

    def get_search_string(self):
        search_string = self.search_string.get()

        filter_array = []

        if self.filter_reserved.get():
            filter_array.append('status=reserved')
        if self.filter_assigned.get():
            filter_array.append('status=assigned')
        if self.filter_quarantine.get():
            filter_array.append('status=quarantine')

        filter_string = "%s" % ' or '.join(filter_array)

        if search_string:
            search_string = ' and '.join([search_string, filter_string])
        else:
            search_string = filter_string
        # print(search_string)
        return search_string

    def handle_error(self, event):
        self.read_queue()
        if self.error:
            # If we're on loading screen
            if self.loading.winfo_exists():
                self.loading_string.set("Connection failed.")
                self.pb.stop()
                if mbox.askretrycancel("Error", self.error['msg']) and not self.ipam_connect_thread.isAlive():
                    self.loading_string.set("Connecting to %s ..." % self.nipap_config['host'])
                    if 'callback' in self.error:
                        self.error['callback']()
                    self.pb.start()
                else:
                    self.quit()
            else:
                self.status.set(self.error['msg'])
                if mbox.askretrycancel("Error", self.error['msg']):
                    if 'callback' in self.error:
                        self.error['callback']()
                else:
                    self.quit()
        self.error = {}

    def define_icons(self):
        """
        Creates references for all images used
        :return:
        """
        self.icon_host = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'host.gif'))
        self.icon_host_reserved = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'host_reserved.gif'))
        self.icon_host_quarantine = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'host_quarantine.gif'))

        self.icon_assignment = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'assignment.gif'))
        self.icon_assignment_reserved = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'assignment_reserved.gif'))
        self.icon_assignment_quarantine = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'assignment_quarantine.gif'))

        self.icon_reservation = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'reservation.gif'))
        self.icon_reservation_reserved = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'reservation_reserved.gif'))
        self.icon_reservation_quarantine = tk.PhotoImage(
            file=os.path.join(self.resources_path, 'reservation_quarantine.gif'))

        self.icon_arrow = tk.PhotoImage(file=os.path.join(self.resources_path, 'arrow.gif'))

        self.icon_free = tk.PhotoImage(file=os.path.join(self.resources_path, 'free.gif'))

    def create_layout(self):
        """
        Creates main layout window
        :return:
        """

        self.rowconfigure(0, weight=0)  # header
        self.rowconfigure(1, weight=1)  # body
        self.rowconfigure(0, weight=0)  # footer

        self.create_header()
        self.create_body()
        self.create_footer()

    def create_header(self):
        """
        Creates header in row 0 of main window
        :return:
        """

        # Main header Frame
        self.header = ttk.Frame(self)
        self.header.columnconfigure(1, weight=1)  # search bar
        self.header.grid(column=0, row=0, sticky=tk.E + tk.W)

        # Search Label and Entry field
        self.search_label = ttk.Label(self.header, text="Prefix search:")
        self.search_label.grid(row=0, column=0, sticky=tk.E)

        self.search = ttk.Entry(self.header, textvariable=self.search_string)
        self.search.grid(row=0, column=1, columnspan=2, sticky=tk.E + tk.W, padx=10, pady=5)
        self.search.bind('<Return>', self.run_search)

        # VRF OptionMenu selection
        self.lock.acquire()
        print(self.vrf_list.keys())
        self.current_vrf.set(list(self.vrf_list.keys())[0])
        self.om = ttk.OptionMenu(self.header, self.current_vrf, self.current_vrf.get(), *self.vrf_list,
                                 command=self.run_search)
        self.lock.release()
        #self.om.config(indicatoron=0, compound='right', image=self.icon_arrow)
        self.om.config(compound='right', image=self.icon_arrow)
        self.om.grid(row=0, column=3, sticky=tk.E + tk.W)

        # Vlan ID Label and Entry field
        self.vlan_label = ttk.Label(self.header, text="Vlan ID:")
        self.vlan_label.grid(row=1, column=0, sticky=tk.E)

        self.vlan_entry = ttk.Entry(self.header)
        self.vlan_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        self.vlan_entry.bind('<Return>', self.run_search)

        # Checkboxes for prefix statuses
        self.checkboxes = ttk.Frame(self.header)
        self.checkboxes.grid(row=1, column=3)
        self.chk_reserved = ttk.Checkbutton(self.checkboxes, text="Reserved", variable=self.filter_reserved,
                                            command=self.run_search)
        self.chk_reserved.pack(side=tk.LEFT)
        self.chk_assigned = ttk.Checkbutton(self.checkboxes, text="Assigned", variable=self.filter_assigned,
                                            command=self.run_search)
        self.chk_assigned.pack(side=tk.LEFT)
        self.chk_quarantine = ttk.Checkbutton(self.checkboxes, text="Quarantine", variable=self.filter_quarantine,
                                              command=self.run_search)
        self.chk_quarantine.pack(side=tk.LEFT)

    def create_body(self):
        self.body = ttk.Frame(self, padding=10)
        self.body.grid(column=0, row=1, sticky=tk.N + tk.S + tk.E + tk.W)
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(0, weight=1)
        self.tabs = ttk.Notebook(self.body)
        self.tabs.grid(sticky=tk.N + tk.S + tk.E + tk.W)

        self.ipv4 = ttk.Frame(self.tabs)
        self.ipv4.columnconfigure(0, weight=1)
        self.ipv4.rowconfigure(0, weight=1)
        self.ipv4.grid(sticky=tk.N + tk.S + tk.E + tk.W)
        self.tabs.add(self.ipv4, text="IPv4 prefixes")

        self.tree_scroll_v4 = tk.Scrollbar(self.ipv4)
        self.tree_scroll_v4.grid(column=1, row=0, sticky=tk.E + tk.W + tk.N + tk.S)

        self.ipv6 = ttk.Frame(self.tabs)
        self.ipv6.columnconfigure(0, weight=1)
        self.ipv6.rowconfigure(0, weight=1)
        self.ipv6.grid(sticky=tk.N + tk.S + tk.E + tk.W)
        self.tabs.add(self.ipv6, text="IPv6 prefixes")

        self.tree_scroll_v6 = tk.Scrollbar(self.ipv6)
        self.tree_scroll_v6.grid(column=1, row=0, sticky=tk.E + tk.W + tk.N + tk.S)

        self.create_tree_v4()
        self.create_tree_v6()

    def create_footer(self):
        self.footer = ttk.Frame(self)
        self.footer.grid(column=0, row=2, sticky=tk.E + tk.W)
        self.footer.columnconfigure(1, weight=1)

        self.status_label = ttk.Label(self.footer, textvariable=self.status)
        self.status_label.grid(row=0, column=0, sticky=tk.E + tk.S)

        self.refresh_button = ttk.Button(self.footer, text='Refresh', command=self.run_search)
        self.refresh_button.grid(row=0, column=1, sticky=tk.E)

        self.quit_button = ttk.Button(self.footer, text='Quit', command=self.quit)
        self.quit_button.grid(row=0, column=2, sticky=tk.E)

    def create_tree_v4(self):
        self.create_tree('v4')

    def create_tree_v6(self):
        self.create_tree('v6')

    def create_tree(self, version):

        if version == 'v4':
            if self.tree_v4:
                self.tree_v4.destroy()
            self.tree_v4 = ttk.Treeview(self.ipv4, columns=('vlan', 'util', 'tags', 'node', 'descr', 'comment'),
                                        yscrollcommand=self.tree_scroll_v4.set, style='Nipap.Treeview')
            self.tree_scroll_v4.config(command=self.tree_v4.yview)
            treeview = self.tree_v4
            prefixes = self.prefixes_v4
        elif version == 'v6':
            if self.tree_v6:
                self.tree_v6.destroy()
            self.tree_v6 = ttk.Treeview(self.ipv6, columns=('vlan', 'util', 'tags', 'node', 'descr', 'comment'),
                                        yscrollcommand=self.tree_scroll_v6.set, style='Nipap.Treeview')
            self.tree_scroll_v6.config(command=self.tree_v6.yview)
            treeview = self.tree_v6
            prefixes = self.prefixes_v6
        else:
            raise ValueError("Version must be v4 or v6")

        treeview.column('vlan', width=70, anchor='center', stretch=False)
        treeview.heading('vlan', text='VLAN ID')

        treeview.column('util', width=70, anchor='center', stretch=False)
        treeview.heading('util', text='Used')

        treeview.column('tags', anchor='center')
        treeview.heading('tags', text='Tags')

        treeview.column('node', anchor='center')
        treeview.heading('node', text='Node')

        treeview.column('descr', anchor='w')
        treeview.heading('descr', anchor='w', text='Descriptuon')

        treeview.column('comment', anchor='w')
        treeview.heading('comment', anchor='w', text='Comment')

        self.lock.acquire()
        self.populate_tree(treeview, prefixes)
        self.lock.release()

        # Colorize rows
        # Assigned
        treeview.tag_configure('reservation_assigned', image=self.icon_reservation)
        treeview.tag_configure('assignment_assigned', image=self.icon_assignment)
        treeview.tag_configure('host_assigned', image=self.icon_host)
        # Reserved
        treeview.tag_configure('reservation_reserved', image=self.icon_reservation_reserved)
        treeview.tag_configure('assignment_reserved', image=self.icon_assignment_reserved)
        treeview.tag_configure('host_reserved', image=self.icon_host_reserved)
        # Quarantine
        treeview.tag_configure('reservation_quarantine', image=self.icon_reservation_quarantine)
        treeview.tag_configure('assignment_quarantine', image=self.icon_assignment_quarantine)
        treeview.tag_configure('host_quarantine', image=self.icon_host_quarantine)
        # Selected
        treeview.tag_configure('selected', background='#ddeeff', font=('TkDefaultFont', '8', 'bold'))
        treeview.tag_configure('free', background='#eeffee', image=self.icon_free,
                               font=('TkDefaultFont', '8', 'italic'))

        # Display tree
        treeview.grid(column=0, row=0, sticky=tk.E + tk.W + tk.N + tk.S)

        # Bind RMB to show context menu
        treeview.bind("<Button-3>", self.popup)

    def populate_tree(self, treeview, tree_part):
        """
        Recursively ill `self.tree` TreeView object with prefixes from `tree_part`.
        Marks prefixes (tags them) that match search criteria so they can be displayed differently in tree
        :param tree_part:
        :return:
        """
        # TODO: remember first selected item and position scrollbar position on it

        if not tree_part or 'children' not in tree_part:
            return

        # Iterate trough prefixes from provided part of the tree
        # TODO: separate IPv4 and IPv6 trees
        for p in sorted(tree_part['children'], key=lambda ip: ipaddress.ip_network(ip)):
            # for p in tree_part['children']:
            pd = tree_part['children'][p]

            if pd['prefix'] is None:
                # Insert item into the tree
                treeview.insert(pd['parent'], 'end', iid=p, text=p,
                                values=('', '', 'Free', ''), tags=['free'])
                continue

            # Predefined prefix tags (prefix type from NIPAP)
            default_tag = "%s_%s" % (pd['prefix'].type, pd['prefix'].status)
            prefix_tags = [default_tag, pd['prefix'].type]

            # If prefix data matches the search mark it as selected
            # We need to add tag 'selected' for formatting before adding it to the tree and
            # expand the tree (tree.see()) after adding it to the tree
            if pd['selected']:
                prefix_tags.append('selected')

            # Insert item into the tree
            treeview.insert(pd['parent'], 'end', iid=pd['prefix'].prefix, text=pd['prefix'].display_prefix, values=(
                pd['prefix'].vlan or '',
                "%2.1f%%" % (100 * pd['prefix'].used_addresses / pd['prefix'].total_addresses),
                ', '.join(pd['prefix'].tags.keys()),
                pd['prefix'].node or '',
                pd['prefix'].description or '',
                pd['prefix'].comment or ''
            ), tags=prefix_tags)

            # If prefix matches search criteria expand tree so prefix is visible
            if pd['selected']:
                treeview.see(pd['prefix'].prefix)

            # Call itself with prefix children
            if pd['children']:
                self.populate_tree(treeview, pd)

    def popup(self, event):
        """
        Displays context menu when right clicking TreeView item (row)
        Also selects the TreeView row
        :param event:
        :return:
        """

        if self.tabs.select() == str(self.ipv4):
            print("IPv4")
            treeview = self.tree_v4
        elif self.tabs.select() == str(self.ipv6):
            print("IPv6")
            treeview = self.tree_v6
        else:
            return

        # Get iid for row under mouse pointer
        iid = treeview.identify_row(event.y)
        if iid:
            # Select row
            treeview.selection_set(iid)
            prefix = treeview.item(iid)['text']

            # Disable menu tearoff
            self.tree_menu = tk.Menu(tearoff=0)
            # Define menu items
            if treeview.tag_has('reservation', iid):
                self.tree_menu.add_command(label="Show free prefixes", command=lambda: self.show_free(prefix))
            if treeview.tag_has('reservation', iid):
                self.tree_menu.add_command(label="Add prefix")
            if treeview.tag_has('assignment', iid):
                self.tree_menu.add_command(label="Add host")
            # Change prefix status
            self.tree_status_menu = tk.Menu(tearoff=0)
            self.tree_status_menu.add_command(label="Assigned")
            self.tree_status_menu.add_command(label="Reserved")
            self.tree_status_menu.add_command(label="Quarantine")
            self.tree_menu.add_cascade(label="Change status", menu=self.tree_status_menu)
            self.tree_menu.add_separator()
            self.tree_menu.add_command(label="Copy IP", command=lambda: self.copy_to_clipboard(prefix, 'ip'))
            self.tree_menu.add_command(label="Copy netmask", command=lambda: self.copy_to_clipboard(prefix, 'mask'))
            self.tree_menu.add_command(label="Copy CIDR", command=lambda: self.copy_to_clipboard(prefix, 'cidr'))
            self.tree_menu.add_separator()
            self.tree_menu.add_command(label="Edit")
            self.tree_menu.add_separator()
            if treeview.tag_has('host', iid):
                self.tree_menu.add_command(label="SSH", image=self.icon_host, compound=tk.LEFT)
                self.tree_menu.add_command(label="Telnet")
                self.tree_menu.add_separator()
            self.tree_menu.add_command(label="Delete", activebackground='#770000',
                                       command=lambda: self.delete_prefix(iid))
            # Display menu at mouse position
            self.tree_menu.post(event.x_root, event.y_root)

    def show_free(self, prefix):
        p = self._find_prefix(prefix, self.prefixes)
        if 'children' not in p or not p['children']:
            return
        supernet = p['prefix'].prefix
        prefixes = list(p['children'].keys())
        all_prefixes = IpamCommon.supernet_fill_gaps(supernet, prefixes)
        for mp in all_prefixes:
            if mp not in prefixes:
                p['children'][mp] = {
                    'parent': p['prefix'].prefix,
                    'prefix': None,
                    'children': {}
                }

        p['selected'] = True

        if p['prefix'].family == 4:
            self.create_tree_v4()
            treeview = self.tree_v4
        elif p['prefix'].family == 6:
            self.create_tree_v6()
            treeview = self.tree_v6
        else:
            return

        iid_children = treeview.get_children([prefix])
        if iid_children:
            treeview.see(iid_children[0])
        treeview.see(prefix)
        treeview.selection_set(prefix)

    def _find_prefix(self, prefix, prefix_tree):
        if 'children' in prefix_tree:
            for child in prefix_tree['children']:
                try:
                    if not IpamCommon.is_subnet_of(ipaddress.ip_network(prefix), ipaddress.ip_network(child)):
                        continue
                except TypeError:
                    continue
                if prefix == child:
                    return prefix_tree['children'][child]
                else:
                    return self._find_prefix(prefix, prefix_tree['children'][child])

    def copy_to_clipboard(self, prefix, what):
        """
        Copy prefix info to clipboard
        :param prefix:
        :param what: ['ip', 'mask', 'cidr']
        :return:
        """
        if what not in ('ip', 'mask', 'cidr'):
            return
        # Build IpInterface object (ipv4 or ipv6) from prefix name
        # We're using correct subnet mask (instead of /32 like in database)
        address = ipaddress.ip_interface(prefix)
        # Clear clipboard
        self.clipboard_clear()

        # Set IP address, subnet mask or IP in CIDR notation
        if what == 'ip':
            self.clipboard_append(address.ip)
        elif what == 'mask':
            self.clipboard_append(address.network.netmask)
        elif what == 'cidr':
            self.clipboard_append(address.with_prefixlen)

        # Update clipboard
        self.update()

    def refresh(self, event=None):
        self.read_queue()
        self.separate_ipv4_ipv6()
        self.create_tree_v4()
        self.create_tree_v6()

    def delete_prefix(self, event=None):
        if mbox.askyesno("Delete prefix?", "Prefix %s will be deleted" % event, icon='warning', default='no'):
            print("Prefix deleted")
            self.refresh()

    def separate_ipv4_ipv6(self):
        self.prefixes_v4 = {
            'children': {}
        }
        self.prefixes_v6 = {
            'children': {}
        }
        for prefix, data in self.prefixes['children'].items():
            p = ipaddress.ip_network(prefix)
            if isinstance(p, ipaddress.IPv4Network):
                self.prefixes_v4['children'][prefix] = data
            elif isinstance(p, ipaddress.IPv6Network):
                self.prefixes_v6['children'][prefix] = data


app = GuiThread()
