import os
import paramiko
import shutil
import re
import frida
import sys, time
import argparse
import ast

# Text cmd colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
Bold = '\033[1m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'

title = '''
  __  __       _     _ _        _____                                    _______          _ 
 |  \/  |     | |   (_) |      |  __ \                                  |__   __|        | |
 | \  / | ___ | |__  _| | ___  | |  | |_   _ _ __ ___  _ __   ___ _ __     | | ___   ___ | |
 | |\/| |/ _ \| '_ \| | |/ _ \ | |  | | | | | '_ ` _ \| '_ \ / _ \ '__|    | |/ _ \ / _ \| |
 | |  | | (_) | |_) | | |  __/ | |__| | |_| | | | | | | |_) |  __/ |       | | (_) | (_) | |
 |_|  |_|\___/|_.__/|_|_|\___| |_____/ \__,_|_| |_| |_| .__/ \___|_|       |_|\___/ \___/|_|
                                                      | |                                   
                                                      |_|                                   
'''


class Parser:
    logger = None

    def __init__(self):
        parser = argparse.ArgumentParser(description='Welcome to Mobile Dumper Tool! To start all you need to do is to provide the app name. Automatic OS detection is included. The default is to use ssh tunnle in 127.0.0.1:22, if you dont have an ssh tunnle open please provide the device ip.',
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-n", "--name", required=True, dest="appName", help="Target app", type=str)
        parser.add_argument("-ip", "--device-ip", required=False, dest="DeviceIp", help="Target Device IP", type=str,
                            default='127.0.0.1')
        parser.add_argument("-p", "--device-port", required=False, dest="DevicePort", help="Target Device Port",
                            type=int, default=22)
        parser.add_argument("-ps", "--path", required=False, dest="pathsToDump",
                            help="Target Device Paths, its possible to add multiple paths separated by sapce, 'path1' 'path2' . the default is to dump the bundle and home paths",
                            type=str, nargs='+', default=[])
        parser.add_argument("-d", "--destination", required=False, dest="destination",
                            help="PC destination folder, the default is where the script exist.", type=str)
        args = parser.parse_args()
        self.command_lines = vars(args)


def createDestinationFolderAtPC():
    try:
        if pars.command_lines['destination'] is None:
            pars.command_lines['destination'] = os.path.join(os.getcwd(), pars.command_lines['appName'] + '_dump')
            os.makedirs(pars.command_lines['destination'])
        else:
            pars.command_lines['destination'] = os.path.join(pars.command_lines['destination'],
                                                             pars.command_lines['appName'] + '_dump')
        if not os.path.exists(pars.command_lines['destination']):
            os.makedirs(pars.command_lines['destination'])
        else:
            print(RED + "[-] PC destination path already exist, going to delete this path: ",
                  pars.command_lines['destination'] + RESET)
            shutil.rmtree(pars.command_lines['destination'])
    except Exception as e:
        print(RED + "[**] Error accrue while creating PC folder: ", e + RESET)


def detect_os_type_on_message(message, data):
    try:
        if 'payload' in message:
            if "Android" in message['payload']:
                print(f"[-] OS detected: {message['payload']}")
                pars.command_lines['os'] = "Android"
            elif "iOS" in message['payload']:
                print(f"[-] OS detected: {message['payload']}")
                pars.command_lines['os'] = "iOS"
    except Exception as e:
        print(RED + "[**] Error accrue in detect_os_type_on_message function: ", e + RESET)


def detect_os_type(command_lines):
    try:
        script = """if (Java.available) {
        send("Android");
        Java.perform(hookSystemLoadLibrary);
    } else if (ObjC.available) {
        send("iOS");
    }"""
        print("[-] Detecting device OS type ...")
        session = frida.get_usb_device().attach(command_lines['appName'])
        script = session.create_script(script)
        script.on("message", detect_os_type_on_message)
        script.load()
        time.sleep(1)
        script.unload()
        session.detach()
    except Exception as e:
        print(RED + "[**] Error accrue in detect_os_type function: ", e + RESET)


def setup_ssh_connection():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        pars.command_lines['DeviceIp'],
        pars.command_lines['DevicePort'],
        pars.command_lines['username'],
        pars.command_lines['password']
    )
    sftp = ssh.open_sftp()
    return ssh, sftp


def close_ssh_connection(ssh, sftp):
    sftp.close()
    ssh.close()


def on_message_android(message, data):
    try:

        if 'payload' in message:
            if "/data/app" in message['payload']:
                print("[-] Going to retrieve default bundle path..")
                bundlePath = os.path.dirname(message['payload'])
                print(GREEN + "[-] Bundle Directory Found in: ", bundlePath + RESET)
                pars.command_lines['pathsToDump'].append(bundlePath)
            else:
                print("[-] Going to retrieve default home path..")
                homePath = os.path.dirname(message['payload'])
                print(GREEN + "[-] Home Directory Found in: ", homePath + RESET)
                pars.command_lines['pathsToDump'].append(homePath)
    except Exception as e:
        print(RED + "[**] Error accrue in on_message function while retrieving app PATHs: ", e + RESET)


def on_message_ios(message, data):
    try:
        if 'payload' in message:
            if ".app" in message['payload']:
                bundlePath = os.path.dirname(message['payload'])
                print(GREEN + "[-] Bundle Directory Found in: ", bundlePath + RESET)
                pars.command_lines['pathsToDump'].append(bundlePath)
            else:
                homePath = message['payload']
                print(GREEN + "[-] Home Directory Found in: ", homePath + RESET)
                pars.command_lines['pathsToDump'].append(homePath)
    except Exception as e:
        print(RED + "[**] Error accrue in on_message function while retrieving app PATHs: ", e + RESET)


def sanitize_filename(filename):
    # Replace problematic characters with an underscore
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)
    return sanitized


def CopyFileFromDevice(targetPath, pcFolder, sftp):
    try:
        for item in sftp.listdir_attr(targetPath):
            itemToCopy_path = os.path.join(targetPath, item.filename)
            local_item_filename = sanitize_filename(item.filename)
            local_item_path = os.path.join(pcFolder, local_item_filename)
            if item.longname[0] == 'd':
                os.makedirs(local_item_path)
                sanitizedPath = itemToCopy_path.replace("\\", "/")
                CopyFileFromDevice(fr"{sanitizedPath}", local_item_path, sftp)
                print(f"[-] Stepping into folder: {item.filename}")
            else:
                itemToCopy_path = itemToCopy_path.replace("\\", "/")
                sftp.get(itemToCopy_path, local_item_path)
                # open(local_item_path,"w+") #only for test
                print(f"[-] File copied: {item.filename}")

    except Exception as e:
        print(RED + "[**] Failed to copy: ", e + RESET)


# ----------------------------------------------------------------------------------------- MAIN STARTS HERE

script_code_iOS = "send(ObjC.classes.NSBundle.mainBundle().bundlePath().toString()); send(ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME').toString());"
script_code_Android = "Java.perform(function() { var currentApplication = Java.use('android.app.ActivityThread').currentApplication(); var context = currentApplication.getApplicationContext(); send(context.getPackageCodePath()); send(context.getFilesDir().getAbsolutePath()); });"

print(CYAN + title + RESET)
pars = Parser()
counter = 1
try:
    detect_os_type(pars.command_lines)

except Exception as e:
    print(RED + "[**] Error accrue while trying to detect OS type: ", e + RESET)

if 'os' in pars.command_lines:
    try:
        createDestinationFolderAtPC()

        if pars.command_lines['os'] == 'iOS':
            pars.command_lines['username'] = 'mobile'
            pars.command_lines['password'] = 'alpine'
            session = frida.get_usb_device().attach(pars.command_lines['appName'])
            if len(pars.command_lines['pathsToDump']) == 0:
                script = session.create_script(script_code_iOS)
                script.on("message", on_message_ios)
                script.load()
                session.detach()

        if pars.command_lines['os'] == 'Android':
            pars.command_lines['username'] = 'root'
            pars.command_lines['password'] = 'admin'

            session = frida.get_usb_device().attach(pars.command_lines['appName'])
            if len(pars.command_lines['pathsToDump']) == 0:
                script = session.create_script(script_code_Android)
                script.on("message", on_message_android)
                script.load()
                session.detach()

    except Exception as e:
        print(RED + "Failed To Dump Folders From Device: ", e + RESET)
    finally:
        ssh, sftp = setup_ssh_connection()
        for path in pars.command_lines['pathsToDump']:
            CopyFileFromDevice(path, pars.command_lines['destination'], sftp)
        close_ssh_connection(ssh, sftp)
        print(GREEN + "\n[$] Dump Finished Successfully" + RESET)
