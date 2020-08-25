import os
import ctypes
import sys
from winreg import *
import binascii
import string
import struct
import zipfile
import json

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

def main():
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
if (is_user_admin() == False):
    print("Failed to execute script! The requested operation requires elevation.")
    sys.exit(1)
else:
    main()
