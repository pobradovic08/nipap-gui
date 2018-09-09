import tkinter as tk
import tkinter.ttk as ttk

import tkinter.messagebox as mbox
import ipaddress
import os
import threading
import queue

from classess import IpamCommon
from classess.queue_message import QueueMessage as QueMsg

from pynipap import Prefix, NipapError


class NipapTypeFrame(ttk.Frame):

    def __init__(self, master, variable, parent=None):
        ttk.Frame.__init__(self, master, padding=4)

        s = ttk.Style()
        s.configure('Disabled.TRadiobutton', foreground='red', state='disabled')

        self.prefix_types = {
            'Reservation': 'reservation',
            'Assignment': 'assignment',
            'Host': 'host'
        }

        if parent:
            if parent.type == 'assignment':
                default = 'host'
            else:
                default = 'assignment'
        else:
            default = None

        for text, val in self.prefix_types.items():
            tmp = ttk.Radiobutton(self, variable=variable, text=text, value=val)
            tmp.pack(anchor=tk.W)
            # Select default value
            if default == val:
                tmp.invoke()
            # If prefix is host, disable everything, if it's assignment disable just host
            if default == 'host' or (default == 'assignment' and val == 'host'):
                tmp.state(('disabled',))



class NipapStatusFrame(ttk.Frame):

    def __init__(self, master, variable, default='assigned'):
        ttk.Frame.__init__(self, master, padding=4)
        self.prefix_statuses = {
            'Reserved': 'reserved',
            'Assigned': 'assigned',
            'Quarantine': 'quarantine'
        }
        for text, val in self.prefix_statuses.items():
            tmp = ttk.Radiobutton(self, variable=variable, text=text, value=val)
            tmp.pack(anchor=tk.W)
            if default == val:
                tmp.invoke()


class NonEmptyEntry(ttk.Entry):

    def __init__(self, master, textvariable, label=None, **kwargs):
        self.textvariable = textvariable
        ttk.Entry.__init__(
            self, master,
            textvariable=self.textvariable,
            **kwargs
        )
        self.label = label
        self.textvariable.trace('w', self.validate_not_empty)
        self.textvariable.set("")

    def validate_not_empty(self, *args):
        if self.textvariable.get() == "":
            if self.label:
                self.label.config(foreground = 'red')
        else:
            if self.label:
                self.label.config(foreground = 'black')

class PrefixEntry(ttk.Entry):

    def __init__(self, master, textvariable, label=None, parent=None, default="", **kwargs):
        self.textvariable = textvariable
        ttk.Entry.__init__(
            self, master,
            textvariable=self.textvariable,
            **kwargs
        )
        self.parent = parent
        self.label = label
        self.textvariable.trace('w', self.validate_not_empty)
        self.textvariable.set(default)

    def validate_not_empty(self, *args):
        try:
            net = ipaddress.ip_network(self.textvariable.get(), strict=False)
            if self.parent:
                parent = ipaddress.ip_network(self.parent.prefix)
                if not IpamCommon.is_subnet_of(net, parent):
                    raise Exception("Not the same subnet")
            if self.label:
                self.label.config(foreground='black')
        except Exception as e:
            if self.label:
               self.label.config(foreground = 'red')


class IpamAddPrefix(tk.Toplevel):

    def __init__(self, master=None, prefix=None, parent=None):
        """

        Open window with form for adding a new prefix

        :param master:
        :param prefix: string
        :param parent: pynipap.Prefix
        """

        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.ipam_add_prefix_thread = None

        self.resources_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../resources'))

        self.prefix = prefix
        self.parent = parent

        tk.Toplevel.__init__(self, master, cursor='left_ptr')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        #self.geometry('640x480')
        # top.attributes('-fullscreen', True)
        self.resizable(False, False)
        icon16_path = os.path.join(self.resources_path, 'icon16.png')
        icon32_path = os.path.join(self.resources_path, 'icon32.png')
        icon16 = tk.PhotoImage(file=icon16_path)
        icon32 = tk.PhotoImage(file=icon32_path)
        self.wm_iconphoto(True, icon32, icon16)
        if parent:
            title = "NIPAP - Add Prefix in %s" % parent.prefix
        else:
            title = "NIPAP - Add Prefix"
        self.title(title)

        self.body = ttk.Frame(self, padding=10)
        self.body.rowconfigure(0, weight=1)
        self.body.columnconfigure(0, weight=1)
        self.body.columnconfigure(1, weight=1)
        self.body.grid(sticky=tk.N + tk.S + tk.E + tk.W)

        # Left pane
        self.val_prefix = tk.StringVar()
        self.val_type = tk.StringVar()
        self.val_status = tk.StringVar()
        self.val_vlan = tk.StringVar()
        self.val_description = tk.StringVar()

        # Right pane
        self.val_node = tk.StringVar()
        self.val_customer_id = tk.StringVar()
        self.val_order_id = tk.StringVar()
        self.val_pool = tk.StringVar()
        self.val_monitor = tk.IntVar()
        self.val_tags = tk.StringVar()
        self.val_comment = tk.StringVar()

        # Status bar
        self.status_string = tk.StringVar()

        label_style = ttk.Style()
        label_style.configure('Nipap.Label', font=('TkDefaultFont', 8, 'bold'))

        self.bind('<<nipap_prefix_added>>', self.prefix_added)
        self.bind('<<nipap_error>>', self.handle_error)

        self.display_form()
        self.display_buttons()

    def prefix_added(self, event):
        self.read_queue()

    def handle_error(self, event):
        self.read_queue()

    def read_queue(self):
        while self.queue.qsize():
            try:
                msg = self.queue.get()
                self.lock.acquire()
                if msg.type == QueMsg.TYPE_STATUS:
                    if msg.status == QueMsg.STATUS_OK:
                        self._ok_status(msg.data)
                    elif msg.status == QueMsg.STATUS_NIPAP_ERROR:
                        self._error_status(msg.data)
                    elif msg.status == QueMsg.STATUS_ERROR:
                        self._error_status("Error.")
                        mbox.showerror("Error", msg.data)
                else:
                    print(msg)
                self.lock.release()
                print(msg)
            except queue.Empty:
                pass

    def display_form(self):
        self.form_left = ttk.LabelFrame(self.body, text="Main attributes", padding=10)
        self.form_left.columnconfigure(1, weight=1)
        self.form_left.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E + tk.W, padx=5)
        # Labels left pane
        self.label_prefix = ttk.Label(self.form_left, text='Prefix:', style='Nipap.Label')
        self.label_prefix.grid(row=0, sticky=tk.E + tk.N, padx=10, pady=5)
        self.label_description = ttk.Label(self.form_left, text='Description:', style='Nipap.Label')
        self.label_description.grid(row=1, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='Type:', style='Nipap.Label').grid(row=2, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='Status:', style='Nipap.Label').grid(row=3, sticky=tk.E + tk.N, padx=10, pady=5)
        ttk.Label(self.form_left, text='VLAN ID:', style='Nipap.Label').grid(row=4, sticky=tk.E + tk.N, padx=10, pady=5)


        # Fields left pane
        self.form_prefix = PrefixEntry(
            self.form_left,
            textvariable=self.val_prefix,
            label=self.label_prefix,
            parent=self.parent,
            default=self.prefix or "",
            width=40
        )
        self.form_prefix.grid(column=1, row=0, sticky=tk.E + tk.W)
        self.form_description = NonEmptyEntry(
            self.form_left, textvariable=self.val_description, label=self.label_description
        )
        self.form_description.grid(column=1, row=1, sticky=tk.E + tk.W)
        self.form_type = NipapTypeFrame(self.form_left, self.val_type, self.parent)
        self.form_type.grid(column=1, row=2, sticky=tk.E + tk.W)
        self.form_status = NipapStatusFrame(self.form_left, self.val_status)
        self.form_status.grid(column=1, row=3, sticky=tk.E + tk.W)

        ttk.Entry(self.form_left, textvariable=self.val_vlan).grid(column=1, row=4, sticky=tk.E + tk.W)


        self.form_right = ttk.LabelFrame(self.body, text="Additional attributes", padding=10)
        self.form_right.columnconfigure(1, weight=1)
        self.form_right.grid(row=0, column=1, sticky=tk.N + tk.S + tk.E + tk.W, padx=5)

        # Labels right pane
        ttk.Label(self.form_right, text='Node:', style='Nipap.Label').grid(
            row=0, sticky=tk.E + tk.N, padx=10, pady=5
        )
        self.label_customer_id = ttk.Label(self.form_right, text='Customer ID:', style='Nipap.Label')
        self.label_customer_id.grid(
            row=1, sticky=tk.E + tk.N, padx=10, pady=5
        )
        ttk.Label(self.form_right, text='Order ID:', style='Nipap.Label').grid(
            row=2, sticky=tk.E + tk.N, padx=10, pady=5
        )
        ttk.Label(self.form_right, text='Pool:', style='Nipap.Label').grid(
            row=3, sticky=tk.E + tk.N, padx=10, pady=5
        )
        ttk.Label(self.form_right, text='Monitor:', style='Nipap.Label').grid(
            row=4, sticky=tk.E + tk.N, padx=10, pady=5
        )
        ttk.Label(self.form_right, text='Tags:', style='Nipap.Label').grid(
            row=5, sticky=tk.E + tk.N, padx=10, pady=5
        )
        ttk.Label(self.form_right, text='Comment:', style='Nipap.Label').grid(
            row=6, sticky=tk.E + tk.N, padx=10, pady=5
        )

        # Fields right pane
        self.form_node = ttk.Entry(
            self.form_right, width=40, textvariable=self.val_node
        )
        self.form_node.grid(
            column=1, row=0, sticky=tk.E + tk.W
        )
        ttk.Entry(self.form_right, textvariable=self.val_customer_id).grid(
            column=1, row=1, sticky=tk.E + tk.W
        )
        ttk.Entry(self.form_right, textvariable=self.val_order_id).grid(
            column=1, row=2, sticky=tk.E + tk.W
        )
        ttk.Entry(self.form_right, textvariable=self.val_pool).grid(
            column=1, row=3, sticky=tk.E + tk.W
        )
        ttk.Checkbutton(self.form_right, variable=self.val_monitor).grid(
            column=1, row=4, sticky=tk.W
        )
        ttk.Entry(self.form_right, textvariable=self.val_tags).grid(
            column=1, row=5, sticky=tk.E + tk.W
        )
        self.form_comment = tk.Text(self.form_right, width=20, height=4)
        self.form_comment.grid(column=1, row=6, pady=5, sticky=tk.E + tk.W)

    def display_buttons(self):
        self.footer = ttk.Frame(self.body)
        self.footer.rowconfigure(0, weight=1)
        self.footer.columnconfigure(0, weight=1)
        self.footer.grid(row=1, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)

        self.statusbar = ttk.Label(self.footer, textvariable=self.status_string)
        self.statusbar.grid(row=0, column=0, sticky=tk.W + tk.S)

        self.cancel_button = ttk.Button(self.footer, text='Cancel', command=self.destroy)
        self.cancel_button.grid(row=0, column=1, sticky=tk.E)

        self.add_button = ttk.Button(self.footer, text='Create', command=self.add_prefix)
        self.add_button.grid(row=0, column=2, sticky=tk.E, padx=10)

    # TODO: add all attributes to Prefix
    def add_prefix(self):
        if self.ipam_add_prefix_thread and self.ipam_add_prefix_thread.isAlive():
            print("Already running")
            return
        dumping = {
            "Prefix": self.val_prefix.get(),
            "Type": self.val_type.get(),
            "Status": self.val_status.get(),
            "Vlan ID": self.val_vlan.get(),
            "Description": self.val_description.get(),
            "Node": self.val_node.get(),
            "Customer ID": self.val_customer_id.get(),
            "Order ID": self.val_order_id.get(),
            "Pool": self.val_pool.get(),
            "Monitor": self.val_monitor.get(),
            "Tags": self.val_tags.get(),
            "Comment": self.form_comment.get("1.0", "end-1c")
        }

        for label, value in dumping.items():
            print("%s: %s" % (label, value))

        if self.validate_form():
            self.ipam_add_prefix_thread = threading.Thread(target=self._thread_ipam_add_prefix)
            self.ipam_add_prefix_thread.start()
            self._status("Adding prefix on server...")

    def validate_form(self):
        try:
            net = ipaddress.ip_network(self.val_prefix.get(), strict=False)
            if self.parent:
                parent = ipaddress.ip_network(self.parent.prefix)
                if not IpamCommon.is_subnet_of(net, parent):
                    raise Exception("Entered prefix outside the %s" % self.parent.prefix)
        except Exception as e:
            self._error_status(e)
            return False

        if not self.val_type.get():
            self._error_status("Select prefix type")
            return False

        if not self.val_status.get():
            self._error_status("Select prefix status")
            return False

        if self.val_description.get() == "":
            self._error_status("Description shouldn't be empty")
            return False

        return True

    def _error_status(self, message):
        self.status_string.set(message)
        self.statusbar.config(foreground='red')

    def _status(self, message):
        self.status_string.set(message)
        self.statusbar.config(foreground='black')

    def _ok_status(self, message):
        self.status_string.set(message)
        self.statusbar.config(foreground='green')

    def _thread_ipam_add_prefix(self):
        try:
            vrf_id = self.master.vrf_list.get(self.master.current_vrf.get())
            self.new_prefix = Prefix()
            self.new_prefix.prefix = self.val_prefix.get()
            self.new_prefix.type = self.val_type.get()
            self.new_prefix.status = self.val_status.get()
            # TODO: set vrf
            # self.new_prefix.vrf = self.master.ipam.get_vrf(vrf_id)
            self.new_prefix.description = self.val_description.get()
            self.master.ipam.save_prefix(self.new_prefix)

            tmp_message = "Prefix %s added." % self.new_prefix.prefix
            self.queue.put(QueMsg(QueMsg.TYPE_STATUS, tmp_message, QueMsg.STATUS_OK))
            self.event_generate('<<nipap_prefix_added>>', when='tail')
        except NipapError as e:
            self.queue.put(QueMsg(QueMsg.TYPE_STATUS, e, QueMsg.STATUS_NIPAP_ERROR))
            self.event_generate('<<nipap_error>>', when='tail')
        except Exception as e:
            self.queue.put(QueMsg(QueMsg.TYPE_STATUS, e, QueMsg.STATUS_ERROR))
            self.event_generate('<<nipap_error>>', when='tail')