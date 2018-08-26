import tkinter as tk
import tkinter.font as tkf
from tkinter import ttk
import re
import tkinter.messagebox as mbox

from ipam_backend import IpamBackend


class Application(tk.Frame):

    def __init__(self, master=None):

        self.data = {
            '10.4.0.0/24': {'description': "Test prefix", "vlan": "4", "tags": "tag1, tag2, tag3", 'type': 'r'},
            '10.4.0.1/24': {'description': "Test prefix", "vlan": "4", "tags": "tag1, tag2, tag3", 'type': 'a'},
            '10.4.0.2/24': {'description': "Test prefix", "vlan": "4", "tags": "tag1, tag2, tag3", 'type': 'a'},
            '10.4.0.3/24': {'description': "Test prefix", "vlan": "4", "tags": "tag1, tag2, tag3", 'type': 'h'},
        }

        tk.Frame.__init__(self, master, cursor='left_ptr', padx=10, pady=10)
        top = self.winfo_toplevel()
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        top.geometry('1024x768')
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)
        self.grid(sticky=tk.N + tk.S + tk.E + tk.W)

        self.icon_host = tk.PhotoImage(file='host.gif')
        self.icon_assignment = tk.PhotoImage(file='test.gif')
        self.icon_reservation = tk.PhotoImage(file='test2.gif')

        # Can't call before creating root window
        self.status = tk.StringVar()
        self.search_string = tk.StringVar()
        self.filter_reserved = tk.IntVar(value=1)
        self.filter_assigned = tk.IntVar(value=1)
        self.filter_quarantine = tk.IntVar(value=1)

        self.create_layout()

    def create_layout(self):
        self.create_header()

        self.body = tk.Frame(self, padx=10, pady=10)
        self.body.grid(column=0, row=2, sticky=tk.N + tk.S + tk.E + tk.W)
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(0, weight=1)
        self.create_tree()

        self.create_footer()

    def create_header(self):
        self.header = tk.Frame(self)
        self.header.grid(column=0, row=1, sticky=tk.E + tk.W)
        self.header.columnconfigure(1, weight=1)

        self.search_label = tk.Label(self.header, text="Prefix search:")
        self.search_label.grid(row=0, column=0)

        self.search = tk.Entry(self.header, textvariable=self.search_string, font=('TkDefaultFont', 9, 'bold'))
        self.search.grid(row=0, column=1, sticky=tk.E + tk.W)
        self.search.bind('<Return>', self.refresh)

        self.vrf_list = ('Mainstream', 'AIK')
        self.v = tk.StringVar()
        self.v.set(self.vrf_list[0])
        self.om = tk.OptionMenu(self.header, self.v, *self.vrf_list)
        self.om.grid(row=0, column=3, sticky=tk.E + tk.W)

        self.checkboxes = tk.Frame(self.header)
        self.checkboxes.grid(row=0, column=2)
        self.chk_reserved = tk.Checkbutton(self.checkboxes, text="Reserved", variable=self.filter_reserved)
        self.chk_reserved.pack(side=tk.LEFT)
        self.chk_assigned = tk.Checkbutton(self.checkboxes, text="Assigned", variable=self.filter_assigned)
        self.chk_assigned.pack(side=tk.LEFT)
        self.chk_quarantine = tk.Checkbutton(self.checkboxes, text="Reserved", variable=self.filter_quarantine)
        self.chk_quarantine.pack(side=tk.LEFT)

    def create_footer(self):
        self.footer = tk.Frame(self)
        self.footer.grid(column=0, row=3, sticky=tk.E + tk.W)
        self.footer.columnconfigure(1, weight=1)

        self.status_label = tk.Label(self.footer, textvariable=self.status)
        self.status_label.grid(row=0, column=0, sticky=tk.E + tk.S)

        self.refresh_button = tk.Button(self.footer, text='Refresh', command=self.refresh)
        self.refresh_button.grid(row=0, column=1, sticky=tk.E)

        self.quit_button = tk.Button(self.footer, text='Quit', command=self.quit)
        self.quit_button.grid(row=0, column=2, sticky=tk.E)

    def create_tree(self):
        self.tree_scroll = tk.Scrollbar(self.body)
        self.tree = ttk.Treeview(self.body, columns=('vlan', 'tags', 'descr'), yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.config(command=self.tree.yview)

        self.tree.column('vlan', width=70, anchor='center', stretch=False)
        self.tree.heading('vlan', text='VLAN ID')

        self.tree.column('tags', anchor='center')
        self.tree.heading('tags', text='Tags')

        self.tree.column('descr', anchor='w')
        self.tree.heading('descr', text='Descriptuon')

        # TODO: move to init
        ipam = IpamBackend()
        ipam.search(self.search_string.get())

        self.populate_tree(ipam.db)

        # Colorize rows
        self.tree.tag_configure('reservation', image=self.icon_reservation)
        self.tree.tag_configure('assignment', image=self.icon_assignment)
        self.tree.tag_configure('host', image=self.icon_host)
        self.tree.tag_configure('selected', background='#ddeeff', font=('TkDefaultFont', '9', 'bold'))

        # Display tree
        self.tree.grid(column=0, row=0, sticky=tk.E + tk.W + tk.N + tk.S)
        self.tree_scroll.grid(column=1, row=0, sticky=tk.E + tk.W + tk.N + tk.S)

        # Bind RMB to show context menu
        self.tree.bind("<Button-3>", self.popup)

    def populate_tree(self, prefix):
        # Compile pattern from search string
        pattern = re.compile(self.search_string.get(), re.IGNORECASE)

        # Iterate trough prefixes from provided part of the tree
        for p, pd in prefix['children'].items():

            # If prefix data matches the search mark it as selected
            # We need to add tag 'selected' for formatting before adding it to the tree and
            # expand the tree (tree.see()) after adding it to the tree
            # TODO: find out how to add tag after inserting the item in the tree
            selected = True if self.search_string.get() and self.search_matches_prefix(pattern, pd['prefix']) else False

            prefix_tags = [pd['prefix'].type]

            if selected:
                prefix_tags.append('selected')

            self.tree.insert(pd['parent'], 'end', iid=pd['prefix'].prefix, text=pd['prefix'].display_prefix, values=(
                pd['prefix'].vlan, ', '.join(pd['prefix'].tags.keys()), pd['prefix'].description
            ), tags=prefix_tags)

            if selected:
                self.tree.see(pd['prefix'].prefix)

            if pd['children']:
                self.populate_tree(pd)

    def search_matches_prefix(self, pattern, prefix):
        if not self.search_string.get():
            return False

        match_against = [
            prefix.prefix,
            prefix.description,
            prefix.comment
        ]

        for value in match_against:
            if value and re.search(pattern, value):
                return True


    def popup(self, event):
        """action in event of button 3 on tree view"""
        # select row under mouse
        iid = self.tree.identify_row(event.y)
        if iid:
            # mouse pointer over item
            self.tree.selection_set(iid)

            self.tree_menu = tk.Menu(tearoff=0)

            self.tree_menu.add_command(label="Edit")
            self.tree_menu.add_command(label="Add prefix", state=tk.DISABLED)
            self.tree_menu.add_separator()
            self.tree_menu.add_command(label="SSH")
            self.tree_menu.add_command(label="Telnet")
            self.tree_menu.add_separator()
            self.tree_menu.add_command(label="Delete", activebackground='#770000',
                                       command=lambda: self.delete_prefix(iid))

            self.tree_menu.post(event.x_root, event.y_root)
        else:
            # mouse pointer not over item
            # occurs when items do not fill frame
            # no action required
            pass

    def refresh(self, event=None):
        self.create_tree()
        # self.tree.see('10.4.0.0/24')
        # self.tree.selection_set('10.4.0.0/24')

    def delete_prefix(self, event=None):
        if mbox.askyesno("Delete prefix?", "Prefix %s will be deleted" % event, icon='warning', default='no'):
            print("Prefix deleted")
            self.refresh()


app = Application()
app.master.title('NIPAP GUI')
app.mainloop()
