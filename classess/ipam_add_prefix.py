import tkinter as tk
import tkinter.ttk as ttk

import tkinter.messagebox as mbox
import ipaddress
import os
import threading
import queue

from classess import IpamBackend
from classess import IpamCommon


class NipapTypeFrame(ttk.Frame):

    def __init__(self, master, variable):
        ttk.Frame.__init__(self, master, padding=4)
        self.prefix_types = {
            'Reservation': 'reservation',
            'Assignment': 'assignment',
            'Host': 'host'
        }
        for text, val in self.prefix_types.items():
            ttk.Radiobutton(self, variable=variable,text=text, value=val).pack(anchor=tk.W)


class NipapStatusFrame(ttk.Frame):

    def __init__(self, master, variable):
        ttk.Frame.__init__(self, master, padding=4)
        self.prefix_statuses = {
            'Reserved': 'reserved',
            'Assigned': 'assigned',
            'Quarantine': 'quarantine'
        }
        for text, val in self.prefix_statuses.items():
            ttk.Radiobutton(self, variable=variable,text=text, value=val).pack(anchor=tk.W)


class IpamAddPrefix(tk.Toplevel):

    def __init__(self, master=None):
        self.resources_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../resources'))

        tk.Toplevel.__init__(self, master, cursor='left_ptr')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        # top.attributes('-fullscreen', True)
        self.resizable(False, False)
        # Not working on GNU/Linux
        #self.iconbitmap(os.path.join(self.resources_path, 'nipap-gui.ico'))
        self.title('NIPAP - Add Prefix')

        self.body = ttk.Frame(self, padding=10)
        self.body.rowconfigure(0, weight=1)
        self.body.columnconfigure(0, weight=1)
        self.body.columnconfigure(1, weight=1)
        self.body.grid(sticky=tk.N + tk.S + tk.E + tk.W)

        self.val_type = tk.StringVar()
        self.val_status = tk.StringVar()
        self.val_prefix = tk.StringVar()
        self.val_description = tk.StringVar()
        self.val_vlan = tk.StringVar()
        self.val_comment = tk.StringVar()

        self.val_monitor = tk.IntVar()

        label_style = ttk.Style()
        label_style.configure('Nipap.Label', font=('TkDefaultFont', 8, 'bold'))

        self.display_form()
        self.display_buttons()

    def display_form(self):
        self.form_left = ttk.LabelFrame(self.body, text="Main attributes", padding=10)
        self.form_left.columnconfigure(1, weight=1)
        self.form_left.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E + tk.W, padx=5)
        # Labels left pane
        ttk.Label(self.form_left, text='Prefix:', style='Nipap.Label').grid(row=0, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='Type:', style='Nipap.Label').grid(row=1, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='Status:', style='Nipap.Label').grid(row=2, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='VLAN ID:', style='Nipap.Label').grid(row=3, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='Description:', style='Nipap.Label').grid(row=4, sticky=tk.E + tk.N, padx=10, pady=5)

        # Fields left pane
        ttk.Entry(self.form_left, textvariable=self.val_prefix, width=30).grid(column=1, row=0, sticky=tk.E + tk.W)
        self.form_type = NipapTypeFrame(self.form_left, self.val_type)
        self.form_type.grid(column=1, row=1, sticky=tk.E + tk.W)
        self.form_status = NipapStatusFrame(self.form_left, self.val_status)
        self.form_status.grid(column=1, row=2, sticky=tk.E + tk.W)

        ttk.Entry(self.form_left, textvariable=self.val_vlan).grid(column=1, row=3, sticky=tk.E + tk.W)
        ttk.Entry(self.form_left, textvariable=self.val_description).grid(column=1, row=4, sticky=tk.E + tk.W)

        self.form_right = ttk.LabelFrame(self.body, text="Additional attributes", padding=10)
        self.form_right.columnconfigure(1, weight=1)
        self.form_right.grid(row=0, column=1, sticky=tk.N + tk.S + tk.E + tk.W, padx=5)
        ttk.Label(self.form_right, text='Node:', style='Nipap.Label').grid(row=0, sticky=tk.E + tk.N, padx=10,
                                                                                  pady=5)
        ttk.Label(self.form_right, text='Customer ID:', style='Nipap.Label').grid(row=1, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_right, text='Order ID:', style='Nipap.Label').grid(row=2, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_right, text='Pool:', style='Nipap.Label').grid(row=3, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_right, text='Monitor:', style='Nipap.Label').grid(row=4, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_right, text='Tags:', style='Nipap.Label').grid(row=5, sticky=tk.E + tk.N, padx=10,
                                                                              pady=5)
        ttk.Label(self.form_right, text='Comment:', style='Nipap.Label').grid(row=6, sticky=tk.E + tk.N, padx=10, pady=5)

        ttk.Entry(self.form_right, text='Test 3', width=30).grid(column=1, row=0, sticky=tk.E + tk.W)
        ttk.Entry(self.form_right, text='Test 4').grid(column=1, row=1, sticky=tk.E + tk.W)
        ttk.Entry(self.form_right, text='Test 4').grid(column=1, row=2, sticky=tk.E + tk.W)
        ttk.Entry(self.form_right, text='Test 5').grid(column=1, row=3, sticky=tk.E + tk.W)
        #ttk.Entry(self.form_right, text='Test 6').grid(column=1, row=4, sticky=tk.E + tk.W)
        ttk.Checkbutton(self.form_right, variable=self.val_monitor).grid(column=1, row=4, sticky=tk.W)
        ttk.Entry(self.form_right, text='Test 7').grid(column=1, row=5, sticky=tk.E + tk.W)

        self.form_comment = tk.Text(self.form_right, width=20, height=4)
        self.form_comment.grid(column=1, row=6, pady=5, sticky=tk.E + tk.W)


    def display_buttons(self):
        self.footer = ttk.Frame(self.body)
        self.footer.rowconfigure(0, weight=1)
        self.footer.columnconfigure(0, weight=1)
        self.footer.grid(row=1, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)

        self.cancel_button = ttk.Button(self.footer, text='Cancel', command=self.destroy)
        self.cancel_button.grid(row=0, column=0, sticky=tk.E)

        self.add_button = ttk.Button(self.footer, text='Create', command=self.add_prefix)
        self.add_button.grid(row=0, column=1, sticky=tk.E, padx=10)

    def add_prefix(self):
        print(self.form_comment.get("1.0", "end-1c"))