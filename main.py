import os
import ctypes
import sys
from winreg import *
import binascii
import string
import struct
import zipfile
import json
import getopt
import tkinter as tk
import tkinter.filedialog as filedialog
from tkinter import messagebox

class AdminStateUnknownError(Exception):
    """Cannot determine whether the user is an admin."""
    pass

def is_user_admin():
    # type: () -> bool
    """Return True if user has admin privileges.

    Raises:
        AdminStateUnknownError if user privileges cannot be determined.
    """
    try:
        return os.getuid() == 0
    except AttributeError:
        pass
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError:
        raise AdminStateUnknownError

def decode(proto, data):
    index = 0
    length = len(data)
    msg = dict()
    while index < length:
        item = 128
        key = 0
        left = 0
        while item & 128:
            item = data[index]
            index += 1
            value = (item & 127) << left
            key += value
            left += 7
        field = key >> 3
        wire = key & 7
        if wire == 0:
            item = 128
            num = 0
            left = 0
            while item & 128:
                item = data[index]
                index += 1
                value = (item & 127) << left
                num += value
                left += 7
            continue
        elif wire == 1:
            index += 8
            continue
        elif wire == 2:
            item = 128
            _length = 0
            left = 0
            while item & 128:
                item = data[index]
                index += 1
                value = (item & 127) << left
                _length += value
                left += 7
            last = index
            index += _length
            item = data[last:index]
            if field not in proto:
                continue
            msg[proto[field]] = item
            continue
        elif wire == 5:
            index += 4
            continue
        raise ValueError(
            'invalid wire type: {wire}'.format(wire=wire)
        )
    return msg

def get_extension_id(crx_file):
    with open(crx_file, 'rb') as f:
      f.read(8); # 'Cr24\3\0\0\0'
      data = f.read(struct.unpack('<I', f.read(4))[0])
      crx3 = decode(
        {10000: "signed_header_data"},
        [d for d in data])
    signed_header = decode(
        {1: "crx_id"},
        crx3['signed_header_data'])
    id_dirty = str.translate(
        str(binascii.hexlify(bytearray(signed_header['crx_id']))),
        str.maketrans('0123456789abcdef', string.ascii_lowercase[:16]))
    return id_dirty[2:][:-1]

def get_extension_version(crx_file):
    print()
    with zipfile.ZipFile(crx_file, 'r') as zip:
        print("Listing contents of", crx_file)
        zip.printdir()
        file = zip.read('manifest.json')
    jsoned = json.loads(file)
    return(jsoned["version"])

def extension_install(crx_file, id, version):
    if crx_file and id and version:
        print("Preparing to manually install...")
        extension_path = os.getenv('LOCALAPPDATA') + '\\Google\\Chrome\\User Data\\Default\\Extensions'
        if os.path.exists(extension_path):
            print("Found extensions successfully. Beginning installation.")
        else:
            print("Failed to find extension path. Please specify one.")
            extension_path = str(input("Extension Path: "))
            if os.path.exists(extension_path):
                print("This path does not exist. Cancelling installation.")
                return
            else:
                print("Manual path validated successfully.")
        if os.path.exists(extension_path):
            print("Creating extension directory.")
            try:
                os.mkdir(extension_path + '\\' + str(id))
            except OSError:
                print("Creation of the directory %s failed" % path)
            else:
                print("Created main extension directory successfully.")
            extension_path = extension_path + '\\' + id
            try:
                os.mkdir(extension_path + '\\' + str(version) + '_0')
            except OSError:
                print("Creation of the directory %s failed" % path)
            else:
                print("Created internal directory structure. Extracting...")
            with zipfile.ZipFile(crx_file, 'r') as zip:
                zip.extractall(extension_path + '\\' + str(version) + '_0')

def main_console():
    t = OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist", 0, KEY_ALL_ACCESS)
    whitelisted = []
    try:
        count = 0
        while 1:
            name, value, type = EnumValue(t, count)
            whitelisted.append(str(value))
            count = count + 1
    except WindowsError:
        pass
    print("Found", count, "extensions already whitelisted.")
    for index in range(len(whitelisted)):
        print(str(index + 1) + ': ' + whitelisted[index])
    print()
    file_path = str(input("Please enter the path to an extension: "))
    id = get_extension_id(file_path)
    if id in whitelisted:
        print("Warning: Extension is already whitelisted.")
    else:
        try:
            SetValueEx(t, str(count + 1), 0, REG_SZ, id)
        except WindowsError:
            pass
        finally:
            print("Successfully added", repr(id), "to extension whitelist.")
    version = get_extension_version(file_path)
    print("Please install the extension by dragging it on to the extension window on Chrome.")
    #extension_install(file_path, id, version)

def main_gui():
    print("Initiating GUI...")
    root = tk.Tk()
    main_window = core_gui(root)
    root.mainloop()

class core_gui:
    def __init__(self, master):
        self.master = master
        master.title("Chrome Extension Installer")

        self.label = tk.Label(master, text="Currently Installed:", font=("Noto Sans", 16))
        self.label.pack(pady=5, padx=20, anchor=tk.NW)

        t = OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist", 0, KEY_ALL_ACCESS)
        whitelisted = []
        try:
            count = 0
            while 1:
                name, value, type = EnumValue(t, count)
                whitelisted.append(str(value))
                count = count + 1
        except WindowsError:
            pass

        whitelist = ''
        for index in range(len(whitelisted)):
            whitelist += str(index + 1) + ':  ' + whitelisted[index]
            if index != len(whitelisted) - 1:
                whitelist += '\n'

        self.console = tk.Listbox(master, font=("Noto Sans", 11), width=40, highlightthickness=0)
        self.console.pack(padx=20, pady=10, anchor=tk.S, fill=tk.BOTH, expand=1)
        self.console.bind('<Double-Button>', core_gui.on_select)
        core_gui.populate_list(self.console, whitelisted, True)

        self.installFrame = tk.Frame(master)
        self.installFrame.pack(padx=0, pady=0, fill=tk.X, expand=1, side=tk.LEFT)
        self.installFrame.label = tk.Label(self.installFrame, font=("Noto Sans", 10), text="File:")
        self.installFrame.label.pack(padx=5, pady=0, anchor=tk.SW)
        self.installFrame.text = tk.Entry(self.installFrame, font=("Noto Sans", 10))
        self.installFrame.text.pack(padx=10, pady=5, anchor=tk.SW, fill=tk.X, expand=1)

        self.installFrame.install_button = tk.Button(self.installFrame, font=("Noto Sans", 10), text="Whitelist", command=self.install_plugin)
        self.installFrame.install_button.pack(padx=10, pady=10, ipadx=5, ipady=5, anchor=tk.SE, side=tk.LEFT, fill=tk.X, expand=1)
        self.installFrame.browse_button = tk.Button(self.installFrame, font=("Noto Sans", 10), text="Browse", command=self.browse_button_action)
        self.installFrame.browse_button.pack(padx=10, pady=10, ipadx=5, ipady=5, anchor=tk.SE, side=tk.LEFT)

    def install_plugin(self):
        if self.installFrame.text.get():
            file_path = self.installFrame.text.get()
            print("Whitelisting from", file_path)
            t = OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist", 0, KEY_ALL_ACCESS)
            whitelisted = []
            try:
                count = 0
                while 1:
                    name, value, type = EnumValue(t, count)
                    whitelisted.append(str(value))
                    count = count + 1
            except WindowsError:
                pass
        id = get_extension_id(file_path)
        if id in whitelisted:
            messagebox.showwarning('Already Whitelisted.', 'This extension ID is already whitelisted. Check to see if you have the correct file and try again.')
        else:
            try:
                SetValueEx(t, str(count + 1), 0, REG_SZ, id)
            except WindowsError:
                pass
            finally:
                t = OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist", 0, KEY_ALL_ACCESS)
                whitelisted = []
                try:
                    count = 0
                    while 1:
                        name, value, type = EnumValue(t, count)
                        whitelisted.append(str(value))
                        count = count + 1
                except WindowsError:
                    pass
                messagebox.showinfo('Whitelist complete.', 'Program successfully whitelisted the given extension.')
                self.populate_list(self.console, whitelisted, True)
        version = get_extension_version(file_path)

    def browse_button_action(self):
        filename = filedialog.askopenfilename()
        if filename.endswith('.crx'):
            print(repr(filename))
            core_gui.set_text(self.installFrame.text, filename, True)
        else:
            messagebox.showwarning('Failed to install.', 'Please select a \'.crx\' file.')

    def add_to_clipboard(text):
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update() # now it stays on the clipboard after the window is closed
        r.destroy()

    def on_select(event):
        w = event.widget
        index = int(w.curselection()[0])
        value = w.get(index)
        core_gui.add_to_clipboard(value)

    def populate_list(listbox, content, clearfirst):
        if clearfirst == True:
            listbox.delete(0, tk.END)
        for index in range(len(content)):
            listbox.insert(index + 1, content[index])

    def set_text(textbox, text, clearfirst):
        if clearfirst == True:
            textbox.delete(0, tk.END)
        textbox.insert(tk.END, text)

def parse_arguments(argv):
    for opt in argv:
        if opt == '-h':
            print('Switches:')
            print('-c: Disables the GUI.')
            print('-h: Gets help.')
            sys.exit()
        elif opt == '-c':
            main_console()

def initialise():
    if (is_user_admin() == False):
        print("Failed to execute script! The requested operation requires elevation.")
        sys.exit(1)
    else:
        if sys.argv[1:]:
            parse_arguments(sys.argv[1:])
        else:
            main_gui()
initialise()
