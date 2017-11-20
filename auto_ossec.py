#!/usr/bin/python
#
#                                    Auto-OSSEC Client
#
#  This is the client piece to the client/server pair (ossec_server.py). Auto-OSSEC will create a protocol
#  and allow automatic deployment of OSSEC keys through an enterprise. One of the biggest challenges with
#  OSSEC is the key management pieces which auto-ossec tries to solve. When run, this will pair with the
#  auto_server.py which has OSSEC server installed on it and request a key and pass it through an AES 
#  encrypted tunnel. Once the exchange completes, auto_ossec will integrate the key and rewrite the conf
#  file for you to incorporate the server IP address. View the README.md for usage and how to effecitvely
#  use auto-ossec. This also works with AlienVault pairing.
#
#  Written by: Dave Kennedy and the Binary Defense Systems (BDS) Team
#  Twitter: @HackingDave, @Binary_Defense
#  Website: https://www.binarydefense.com 
#
#  Usage: python auto_ossec.py  - this will show you the flag options to pair. Read the README.md for more
#  information.
#

import platform
import base64
import socket
import sys
import os
import subprocess
import time
try: import urllib.request as urllib
except: import urllib
import traceback

# try to import python-crypto

### TO COMPILE THIS ON WINDOWS AND NOT USE THE EXE PROVIDED IN GITHUB ####

## FIRST:  Download http://aka.ms/vcpython2 (Microsoft Visual C++ 9.0 for Python)
## NEXT: Download and Install: https://www.microsoft.com/en-us/download/details.aspx?id=5555
## NEXT: Download pyinstaller.org (latest version)
## NEXT: Download Python and Install (python.org)
## NEXT: Open up a command prompt, type: PATH=C:\Python27 (or 2 or 3 whatever)
## NEXT: python -m easy_install pycrypto
## NEXT: Unzip pyinstaller, navigate to the directory and type python pyinstaller --onefile auto_ossec.py - this will generate a binary under auto_ossec\dist

try:
    from Crypto.Cipher import AES

except ImportError as e:
    print ("[!] You need python-crypto in order for this module to work. If this is Ubuntu/Redhat - package name is python-crypto")
    print(e)
    sys.exit()

# check platform specific installs
installer = ""
if platform.system() == "Linux": 
    installer = "Linux"

if platform.system() == "Darwin":
    installer = "Darwin"

if platform.system() == "Windows":
    installer = "Windows"

if installer == "":
    print ("[!] Unable to determine operating system. Only supports Linux and Windows. Exiting..")
    sys.exit()


#
# NEED TO DEFINE THIS AS THE OSSEC SERVER HOST THAT IS RUNNING SERVER.PY
#
star = ""
autoinstall = ""
version_name = ""
try:
    host = sys.argv[1]
    try: 
        if "0.0.0.0/0" in sys.argv[2]: star = sys.argv[2]
        else: autoinstall = sys.argv[2]

    except: pass

    try: 
        if "0.0.0.0/0" in sys.argv[3]: star = sys.argv[3]
        else: autoinstall = sys.argv[3]

    except: pass

except IndexError:
    print ("""
Binary Defense Systems (BDS) OSSEC Auto Enrollment
https://www.binarydefense.com
Written by: The BDS Crew: Dave Kennedy, Charles Yost, Jimmy Byrd, Jason Ashton, Eric Itangata

In order for this to work, you need to point auto_ossec.exe to the OSSEC server that is listening. Note that default port is 9654 but this can be changed in the source.

Note that if you specify optional 0.0.0.0/0, this will place a star for the IP address in the config and allow any IP address (for dynamic IP addresses).

Also note if you specify url=<site> at the end, this is for Linux only, it will automatically download and install OSSEC for you and configure it based on the server-ip. You do not need to do a 0.0.0.0/0 before

Example: auto_ossec.exe/.bin 192.168.5.5 0.0.0.0/0 url=https://bintray.com/etc/etc/ossec-hids.tar.gz
Example2: auto_ossec.bin 192.168.5.5 url=https://somewebsite.com/ossec-hids-2.8.3.tar.gz
Usage: auto_ossec.exe <server_ip> <optional: 0.0.0.0/0> <optional: url>

Example URL: https://bintray.com/artifact/download/ossec/ossec-hids/ossec-hids-2.8.3.tar.gz

        """)
    sys.exit()

# url for OSSEC HERE
if "url=" in autoinstall: 
    url = autoinstall.replace("url=", "").replace('"', "", 2)
    version_name = url.split("/ossec-hids/")[1].replace(".tar.gz", "")

if "path=" in autoinstall:
    path = autoinstall.replace("path=", "").replace('"', "", 2)
    if "/" in path:
        _, path_filename = os.path.split(path)
    else:
        path_filename = path
    version_name = path_filename.replace(".tar.gz", "")

# download ossec
def _download_ossec(url):
    ossec_file = urllib.urlopen(url).read()
    filewrite = open("/tmp/ossec.tar.gz", "wb")
    filewrite.write(ossec_file)
    filewrite.close()
    
# MODIFY THIS IF YOU NEED TO CHANGE SOME OF THE BASE OSSEC INSTALL CONFIG OPTIONS    
def _pull_ossec_config(hostname):
    ossec_config = (r"""
<ossec_config>

  <!-- One entry for each file/Event log to monitor. -->
  <localfile>
    <location>Application</location>
    <log_format>eventlog</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventlog</log_format>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventlog</log_format>
  </localfile>


  <!-- Rootcheck - Policy monitor config -->
  <rootcheck>
    <windows_audit>./shared/win_audit_rcl.txt</windows_audit>
    <windows_apps>./shared/win_applications_rcl.txt</windows_apps>
    <windows_malware>./shared/win_malware_rcl.txt</windows_malware>
  </rootcheck>  


   <!-- Syscheck - Integrity Checking config. -->
  <syscheck>
  
    <!-- Default frequency, every 20 hours. It doesn't need to be higher
      -  on most systems and one a day should be enough.
      -->
    <frequency>72000</frequency>

    <!-- By default it is disabled. In the Install you must choose
      -  to enable it.
      -->
    <disabled>no</disabled>  


    <!-- Default files to be monitored - system32 only. -->
    <directories check_all="yes">%WINDIR%/win.ini</directories>
    <directories check_all="yes">%WINDIR%/system.ini</directories>
    <directories check_all="yes">C:\autoexec.bat</directories>
    <directories check_all="yes">C:\config.sys</directories>
    <directories check_all="yes">C:\boot.ini</directories>
    <directories check_all="yes">%WINDIR%/System32/CONFIG.NT</directories>
    <directories check_all="yes">%WINDIR%/System32/AUTOEXEC.NT</directories>
    <directories check_all="yes">%WINDIR%/System32/at.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/attrib.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/cacls.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/debug.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/drwatson.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/drwtsn32.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/edlin.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/eventcreate.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/eventtriggers.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/ftp.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/net.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/net1.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/netsh.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/rcp.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/reg.exe</directories>
    <directories check_all="yes">%WINDIR%/regedit.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/regedt32.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/regsvr32.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/rexec.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/rsh.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/runas.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/sc.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/subst.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/telnet.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/tftp.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/tlntsvr.exe</directories>
    <directories check_all="yes">%WINDIR%/System32/drivers/etc</directories>
    <directories check_all="yes" realtime="yes">C:\Documents and Settings/All Users/Start Menu/Programs/Startup</directories>
    <directories check_all="yes" realtime="yes">C:\Users/Public/All Users/Microsoft/Windows/Start Menu/Startup</directories>
    <ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>

    <!-- Windows registry entries to monitor. -->
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\cmdfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\comfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\exefile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\piffile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\AllFilesystemObjects</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Directory</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Folder</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Protocols</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Policies</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Security</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\URL</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components</windows_registry>


    <!-- Windows registry entries to ignore. -->
    <registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\Security\SAM\Domains\Account\Users</registry_ignore>
    <registry_ignore type="sregex">\Enum$</registry_ignore>
  </syscheck>    

  <active-response>
    <disabled>yes</disabled>
  </active-response>

   <client>
      <server-ip>REPLACEHERE</server-ip>
   </client>
 </ossec_config>""")
 
    return ossec_config.replace("<server-ip>REPLACEHERE</server-ip>", "<server-ip>%s</server-ip>" % (host))
 
# install ossec once downloaded
def _installossec(serverip,version_name):
    cwd = os.getcwd()
    os.chdir("/tmp/")
    subprocess.Popen("tar -zxvf ossec.tar.gz;rm ossec.tar.gz", shell=True).wait()

    #####
    #####
    ##### CHANGE THESE IF YOU WANT DIFFERENT CONFIG OPTIONS - read: http://ossec-docs.readthedocs.io/en/latest/manual/installation/install-source-unattended.html
    #####
    #####
    ossec_preload = ('''
                    USER_LANGUAGE="en"
                    USER_NO_STOP="y"
                    USER_INSTALL_TYPE="agent"
                    USER_DIR="/var/ossec"
                    USER_ENABLE_ACTIVE_RESPONSE="n"
                    USER_ENABLE_SYSCHECK="y"
                    USER_ENABLE_ROOTCHECK="y"
                    USER_UPDATE_RULES="y"
                    USER_AGENT_SERVER_IP="%s"
                    USER_ENABLE_EMAIL="n"
                    USER_ENABLE_FIREWALL_RESPONSE="n"
                    ''' % (serverip))

    filewrite = open("/tmp/%s/etc/preloaded-vars.conf" % (version_name), "w")
    filewrite.write(ossec_preload)
    filewrite.close()
    subprocess.Popen("cd %s;chmod +x;./install.sh" % (version_name), shell=True).wait()
    subprocess.Popen("rm -rf /tmp/%s" % (version_name), shell=True).wait()

# this is the auto installation process here
if installer in "Linux|Darwin":
    if "url=" in autoinstall:
        print("[*] Automatically installing OSSEC on Linux for you with version: " + (version_name))
        _download_ossec(url)
        _installossec(host,version_name)

    if "path=" in autoinstall:
        print("[*] Automatically installing OSSEC on Linux for you with version: " + (version_name))
        from shutil import copyfile
        copyfile(path, '/tmp/ossec.tar.gz')
        _installossec(host,version_name)


def aescall(secret, data, format):
    # padding and block size
    PADDING = '{'
    BLOCK_SIZE = 32
    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # random value here to randomize builds
    a = 50 * 5

    # one-liners to encrypt/encode and decrypt/decode a string
    encryptaes = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    decryptaes = lambda c, e: str(c.decrypt(base64.b64decode(e)), 'UTF-8').rstrip(PADDING)

    decryptaes_py2 = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    cipher = AES.new(secret)

    if format == "encrypt":
        aes = encryptaes(cipher, data)
        return aes

    if format == "decrypt":
        try: aes = decryptaes(cipher, data)
        except TypeError: aes = decryptaes_py2(cipher, data)
        return str(aes)

# this will grab the hostname and ip address and return it
def grab_info():
    try:
        hostname = socket.gethostname()
        return hostname  # + " " + ipaddr

    except Exception:
        sys.exit()
try:
    # secret key - if you change this you must change on ossec_auto server -
    # would recommend this is the default published to git
    secret = "(3j+-sa!333hNA2u3h@*!~h~2&^lk<!B"
    # port for daemon
    port = 9654
    # general length size of socket
    size = 1024

    # loop through in case server isnt reachable
    while 1:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            break

        except Exception:
            print ("[!] Unable to connect to destination server. Re-trying in 10 seconds.")
            time.sleep(10)
            pass

    print(("[*] Connected to auto enrollment server at IP: " + host))
    # grab host info needed for ossec
    data = grab_info()

    # encrypt the data
    if star == "0.0.0.0/0": data = "BDSOSSEC*" + data.rstrip()
    else: data = "BDSOSSEC" + data.rstrip()
    data = aescall(secret, data, "encrypt")
    print ("[*] Pulled hostname and IP, encrypted data, and now sending to server.")
    s.send(data)
    data = s.recv(size)
    # this is our ossec key
    print ("[*] We received our new pairing key for OSSEC, closing server connection.")
    data = aescall(secret, data, "decrypt")
    # close socket
    s.close()

    # path variables for OSSEC
    if os.path.isdir("C:\\Program Files (x86)\\ossec-agent"): path = "C:\\Program Files (x86)\\ossec-agent"
    if os.path.isdir("C:\\Program Files\\ossec-agent"): path = "C:\\Program Files\\ossec-agent"
    if os.path.isdir("/var/ossec/"): path = "/var/ossec/"
    if path == "": sys.exit()
    print ("[*] Removing any old keys.")
    os.chdir(path)

    if installer == "Windows":
        if os.path.isfile("client.keys"): os.remove("client.keys")
        # import the key with the key presented from the server daemon
        filewrite = open(path + "\\client.keys", "w")

    if installer in "Linux|Darwin":
        if os.path.isfile(path + "/etc/client.keys"): os.remove("etc/client.keys")
        filewrite = open(path + "/etc/client.keys", "w")

    data = base64.b64decode(data)
    # python 2 to 3 compatibility
    try: data = str(data, 'UTF-8')
    except TypeError: data = str(data)
    filewrite.write(data)
    filewrite.close()
    print ("[*] Successfully imported the new pairing key.")
    print ("[*] Stopping the OSSEC service, just in case its running.")
    # stop the service if it is
    if installer == "Windows":
        subprocess.Popen('net stop "OSSEC HIDS"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
    # Linux and OSX
    if installer in "Linux|Darwin":
        subprocess.Popen("/var/ossec/bin/ossec-control stop", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    # make sure we modify the ossec.conf
    if installer == "Windows":
        if os.path.isfile(path + "\\ossec.conf"):
            print ("[*] Overwriting the ossec.conf to incorporate server host IP address.")
            ossec_config = _pull_ossec_config(host)
            filewrite = open(path + "\\ossec.conf", "w")
            filewrite.write(ossec_config)
            filewrite.close()
        else: 
            print("[!] Unable to find the ossec.conf file in: " + path + "\\ossec.conf")
            print("[!] Please install OSSEC first before running any of this.")
            sys.exit()

    # start the service
    if installer == "Windows":
        subprocess.Popen('net start "OSSEC HIDS"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    if installer in "Linux|Darwin":
        subprocess.Popen("service ossec start", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    print ("[*] Finished. Started the OSSEC service. Auto Enrollment for OSSEC is now finished.")

except KeyboardInterrupt:
    print ("Sounds good.. Aborting Auto-OSSEC...")
    sys.exit()

except Exception as error:
    print ("[*] Something did not complete. Does this system have Internet access?")
    print(traceback.print_exc(file=sys.stdout))
