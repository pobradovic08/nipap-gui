import tkinter as tk
import tkinter.font as tkf
from tkinter import ttk
import re
import tkinter.messagebox as mbox
import ipaddress

import time
import threading
import random
import queue

from ipam_backend import IpamBackend


class GuiThread:

    def __init__(self):
        app = NipapGui()
        app.master.title('NIPAP GUI')
        app.mainloop()


class NipapGui(tk.Frame):

    def __init__(self, master=None):

        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.prefixes = {}

        self.ipam_search_thread = None

        # Spawn a thread for nipap initial connect
        self.ipam_connect_thread = threading.Thread(target=self.thread_ipam_connect)
        self.ipam_connect_thread.start()

        tk.Frame.__init__(self, master, cursor='left_ptr', padx=10, pady=10)
        top = self.winfo_toplevel()
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        top.geometry('1024x768')
        top.iconbitmap('nipap-gui.ico')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.grid(sticky=tk.N + tk.S + tk.E + tk.W)

        self.define_icons()

        # Can't call before creating root window
        self.status = tk.StringVar()
        self.search_string = tk.StringVar()
        self.current_vrf = tk.StringVar()
        self.filter_reserved = tk.IntVar(value=1)
        self.filter_assigned = tk.IntVar(value=1)
        self.filter_quarantine = tk.IntVar(value=1)

        self.bind('<<nipap_connected>>', self.connected)
        self.bind('<<nipap_refresh>>', self.refresh)

        self.display_loading()

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
        self.loading = tk.Frame(self)
        # self.loading.rowconfigure(0, weight=1)
        # self.loading.columnconfigure(0, weight=1)
        self.loading.grid(row=0, column=0)

        label = tk.Label(self.loading, text="Connecting to server...")
        label.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E + tk.W)
        self.pb = tk.ttk.Progressbar(self.loading, mode='indeterminate')
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
                self.lock.release()
                print(msg)
            except queue.Empty:
                pass

    def thread_ipam_connect(self):
        self.ipam = IpamBackend(self.queue)
        try:
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
        self.ipam.search(self.search_string.get(), vrf_id)
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

    def define_icons(self):
        """
        Creates references for all images used
        :return:
        """
        self.icon_host = tk.PhotoImage(file='host.gif')
        self.icon_host_reserved = tk.PhotoImage(file='host_reserved.gif')
        self.icon_host_quarantine = tk.PhotoImage(file='host_quarantine.gif')

        self.icon_assignment = tk.PhotoImage(file='assignment.gif')
        self.icon_assignment_reserved = tk.PhotoImage(file='assignment_reserved.gif')
        self.icon_assignment_quarantine = tk.PhotoImage(file='assignment_quarantine.gif')

        self.icon_reservation = tk.PhotoImage(file='reservation.gif')
        self.icon_reservation_reserved = tk.PhotoImage(file='reservation_reserved.gif')
        self.icon_reservation_quarantine = tk.PhotoImage(file='reservation_quarantine.gif')

        self.icon_arrow = tk.PhotoImage(file='arrow.gif')

    def create_layout(self):
        """
        Creates main layout window
        :return:
        """

        self.rowconfigure(0, weight=0) # header
        self.rowconfigure(1, weight=1) # body
        self.rowconfigure(0, weight=0) # footer

        self.create_header()
        self.create_body()
        self.create_footer()

    def create_header(self):
        """
        Creates header in row 0 of main window
        :return:
        """

        # Main header Frame
        self.header = tk.Frame(self)
        self.header.columnconfigure(1, weight=1) # search bar
        self.header.grid(column=0, row=0, sticky=tk.E + tk.W)

        # Search Label and Entry field
        self.search_label = tk.Label(self.header, text="Prefix search:")
        self.search_label.grid(row=0, column=0, sticky=tk.E)

        self.search = tk.Entry(self.header, textvariable=self.search_string, font=('TkDefaultFont', 9, 'bold'))
        self.search.grid(row=0, column=1, columnspan=2, sticky=tk.E + tk.W)
        self.search.bind('<Return>', self.run_search)

        # VRF OptionMenu selection
        self.current_vrf.set(list(self.vrf_list.keys())[0])
        self.om = tk.OptionMenu(self.header, self.current_vrf, *self.vrf_list, command=self.refresh)
        self.om.config(indicatoron=0, compound='right', image=self.icon_arrow)
        self.om.grid(row=0, column=3, sticky=tk.E + tk.W)

        # Vlan ID Label and Entry field
        self.vlan_label = tk.Label(self.header, text="Vlan ID:")
        self.vlan_label.grid(row=1, column=0, sticky=tk.E)

        self.vlan_entry = tk.Entry(self.header)
        self.vlan_entry.grid(row=1, column=1, sticky=tk.W)
        self.vlan_entry.bind('<Return>', self.run_search)

        # Checkboxes for prefix statuses
        self.checkboxes = tk.Frame(self.header)
        self.checkboxes.grid(row=1, column=3)
        self.chk_reserved = tk.Checkbutton(self.checkboxes, text="Reserved", variable=self.filter_reserved)
        self.chk_reserved.pack(side=tk.LEFT)
        self.chk_assigned = tk.Checkbutton(self.checkboxes, text="Assigned", variable=self.filter_assigned)
        self.chk_assigned.pack(side=tk.LEFT)
        self.chk_quarantine = tk.Checkbutton(self.checkboxes, text="Quarantine", variable=self.filter_quarantine)
        self.chk_quarantine.pack(side=tk.LEFT)

    def create_body(self):
        self.body = tk.Frame(self, padx=10, pady=10)
        self.body.grid(column=0, row=1, sticky=tk.N + tk.S + tk.E + tk.W)
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(0, weight=1)
        self.create_tree()

    def create_footer(self):
        self.footer = tk.Frame(self)
        self.footer.grid(column=0, row=2, sticky=tk.E + tk.W)
        self.footer.columnconfigure(1, weight=1)

        self.status_label = tk.Label(self.footer, textvariable=self.status)
        self.status_label.grid(row=0, column=0, sticky=tk.E + tk.S)

        self.refresh_button = tk.Button(self.footer, text='Refresh', command=self.run_search)
        self.refresh_button.grid(row=0, column=1, sticky=tk.E)

        self.quit_button = tk.Button(self.footer, text='Quit', command=self.quit)
        self.quit_button.grid(row=0, column=2, sticky=tk.E)

    def create_tree(self):
        self.tree_scroll = tk.Scrollbar(self.body)
        self.tree = ttk.Treeview(self.body, columns=('vlan', 'tags', 'descr', 'comment'), yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.config(command=self.tree.yview)

        self.tree.column('vlan', width=70, anchor='center', stretch=False)
        self.tree.heading('vlan', text='VLAN ID')

        self.tree.column('tags', anchor='center')
        self.tree.heading('tags', text='Tags')

        self.tree.column('descr', anchor='w')
        self.tree.heading('descr', anchor='w', text='Descriptuon')

        self.tree.column('comment', anchor='w')
        self.tree.heading('comment', anchor='w', text='Comment')

        self.lock.acquire()
        self.populate_tree(self.prefixes)
        self.lock.release()

        # Colorize rows
        # Assigned
        self.tree.tag_configure('reservation_assigned', image=self.icon_reservation)
        self.tree.tag_configure('assignment_assigned', image=self.icon_assignment)
        self.tree.tag_configure('host_assigned', image=self.icon_host)
        # Reserved
        self.tree.tag_configure('reservation_reserved', image=self.icon_reservation_reserved)
        self.tree.tag_configure('assignment_reserved', image=self.icon_assignment_reserved)
        self.tree.tag_configure('host_reserved', image=self.icon_host_reserved)
        # Quarantine
        self.tree.tag_configure('reservation_quarantine', image=self.icon_reservation_quarantine)
        self.tree.tag_configure('assignment_quarantine', image=self.icon_assignment_quarantine)
        self.tree.tag_configure('host_quarantine', image=self.icon_host_quarantine)
        # Selected
        self.tree.tag_configure('selected', background='#ddeeff', font=('TkDefaultFont', '9', 'bold'))

        # Display tree
        self.tree.grid(column=0, row=0, sticky=tk.E + tk.W + tk.N + tk.S)
        self.tree_scroll.grid(column=1, row=0, sticky=tk.E + tk.W + tk.N + tk.S)

        # Bind RMB to show context menu
        self.tree.bind("<Button-3>", self.popup)

    def populate_tree(self, tree_part):
        """
        Recursively ill `self.tree` TreeView object with prefixes from `tree_part`.
        Marks prefixes (tags them) that match search criteria so they can be displayed differently in tree
        :param tree_part:
        :return:
        """
        # Compile pattern from search string
        pattern = re.compile(self.search_string.get(), re.IGNORECASE)

        if not tree_part or 'children' not in tree_part:
            return

        # Iterate trough prefixes from provided part of the tree
        for p, pd in tree_part['children'].items():

            # If prefix data matches the search mark it as selected
            # We need to add tag 'selected' for formatting before adding it to the tree and
            # expand the tree (tree.see()) after adding it to the tree
            # TODO: remember first selected item and position scrollbar position on it
            selected = True if self.search_string.get() and self.search_matches_prefix(pattern, pd['prefix']) else False

            # Predefined prefix tags (prefix type from NIPAP)
            default_tag = "%s_%s" % (pd['prefix'].type, pd['prefix'].status)
            prefix_tags = [default_tag, pd['prefix'].type]

            # Append selected tag if needed
            if selected:
                prefix_tags.append('selected')

            # Insert item into the tree
            self.tree.insert(pd['parent'], 'end', iid=pd['prefix'].prefix, text=pd['prefix'].display_prefix, values=(
                pd['prefix'].vlan or '',
                ', '.join(pd['prefix'].tags.keys()),
                pd['prefix'].description or '',
                pd['prefix'].comment or ''
            ), tags=prefix_tags)

            # If prefix matches search criteria expand tree so prefix is visible
            if selected:
                self.tree.see(pd['prefix'].prefix)

            # Call itself with prefix children
            if pd['children']:
                self.populate_tree(pd)

    def search_matches_prefix(self, pattern, prefix):
        """
        Returns True if any of defined prefix attributes matches search criteria
        :param pattern: Compiled re expression
        :param prefix: pynipap Prefix object
        :return:
        """

        # If the search string is empty or none don't mark any prefixes
        if not self.search_string.get():
            return False

        # List of values to check
        match_against = [
            prefix.prefix,
            prefix.description,
            prefix.comment
        ]

        # Search for `pattern` in list of values
        for value in match_against:
            if value and re.search(pattern, value):
                return True

    def popup(self, event):
        """
        Displays context menu when right clicking TreeView item (row)
        Also selects the TreeView row
        :param event:
        :return:
        """
        # Get iid for row under mouse pointer
        iid = self.tree.identify_row(event.y)
        if iid:
            # Select row
            self.tree.selection_set(iid)
            prefix = self.tree.item(iid)['text']

            # Disable menu tearoff
            self.tree_menu = tk.Menu(tearoff=0)
            # Define menu items
            self.tree_menu.add_command(label="Copy IP", command=lambda: self.copy_to_clipboard(prefix, 'ip'))
            self.tree_menu.add_command(label="Copy netmask", command=lambda: self.copy_to_clipboard(prefix, 'mask'))
            self.tree_menu.add_command(label="Copy CIDR", command=lambda: self.copy_to_clipboard(prefix, 'cidr'))
            self.tree_menu.add_separator()
            self.tree_menu.add_command(label="Edit")
            self.tree_status_menu = tk.Menu(tearoff=0)
            self.tree_status_menu.add_command(label="Assigned")
            self.tree_status_menu.add_command(label="Reserved")
            self.tree_status_menu.add_command(label="Quarantine")
            self.tree_menu.add_cascade(label="Change status", menu=self.tree_status_menu)
            if self.tree.tag_has('reservation', iid):
                self.tree_menu.add_command(label="Add prefix")
            if self.tree.tag_has('assignment', iid):
                self.tree_menu.add_command(label="Add host")
            self.tree_menu.add_separator()
            if self.tree.tag_has('host', iid):
                self.tree_menu.add_command(label="SSH", image=self.icon_host, compound = tk.LEFT)
                self.tree_menu.add_command(label="Telnet")
                self.tree_menu.add_separator()
            self.tree_menu.add_command(label="Delete", activebackground='#770000',
                                       command=lambda: self.delete_prefix(iid))
            # Display menu at mouse position
            self.tree_menu.post(event.x_root, event.y_root)

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
        self.create_tree()

    def delete_prefix(self, event=None):
        if mbox.askyesno("Delete prefix?", "Prefix %s will be deleted" % event, icon='warning', default='no'):
            print("Prefix deleted")
            self.refresh()

#app = NipapGui(main_queue=q)
#app.master.title('NIPAP GUI')
#app.mainloop()

app = GuiThread()
