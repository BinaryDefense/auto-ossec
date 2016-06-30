#!/usr/bin/python
#
# This is the initial release of the ossec_client.py which can be byte compiled into an exe. This will
# connect to the ossec_auto.py daemon that will automatically issue a key in order to pair the OSSEC
# HIDS.
#
# Also works with AlienVault.
#
# NOTE that you NEED to change the host = '' to the appropriate IP address of the OSSEC server and
# where the ossec_auto.py daemon is running.
#

import platform
import base64
import socket
import sys
import os
import subprocess
import time

# try to import python-crypto
try:
    from Crypto.Cipher import AES

except ImportError:
    print (
        "[!] You need python-crypto in order for this module to work. If this is Ubuntu/Redhat - package name is python-crypto")
    sys.exit()

# check platform specific installs
installer = ""
if platform.system() == "Linux":
    installer = "Linux"

if platform.system() == "Windows":
    installer = "Windows"

if installer == "":
    print (
        "[!] Unable to determine operating system. Only supports Linux and Windows. Exiting..")
    sys.exit()

#
# NEED TO DEFINE THIS AS THE OSSEC SERVER HOST THAT IS RUNNING SERVER.PY
#
star = ""
try:
    host = sys.argv[1]
    try:
        star = sys.argv[2]
    except:
        pass

except IndexError:
    print ("""
******************************************************
Binary Defense Systems OSSEC Auto Enrollment

In order for this to work, you need to point
auto_ossec.exe to the OSSEC server that is
listening. Note that default port is 9654
but this can be changed in the source.

Note that if you specify optional *, this will
place a * for the IP address in the config and
allow any IP address (for dynamic IP addresses).

Example: auto_ossec.exe/.bin 192.168.5.5 *
Usage: auto_ossec.exe <server_ip> <optional: *>

*****************************************************
		""")
    sys.exit()


def aescall(secret, data, format):

    # padding and block size
    PADDING = '{'
    BLOCK_SIZE = 32
    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # random value here to randomize builds
    a = 50 * 5

    # one-liners to encrypt/encode and decrypt/decode a string
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    cipher = AES.new(secret)

    if format == "encrypt":
        aes = EncodeAES(cipher, data)
        return str(aes)

    if format == "decrypt":
        aes = DecodeAES(cipher, data)
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
            print (
                "[!] Unable to connect to destination server. Re-trying in 10 seconds.")
            time.sleep(10)
            pass

    print(("[*] Connected to auto enrollment server at IP: " + host))
    # grab host info needed for ossec
    data = grab_info()

    # encrypt the data
    if star == "*":
        data = "BDSOSSEC*" + data.rstrip()
    else:
        data = "BDSOSSEC" + data.rstrip()
    data = aescall(secret, data, "encrypt")
    print (
        "[*] Pulled hostname and IP, encrypted data, and now sending to server.")
    s.send(data)
    data = s.recv(size)
    # this is our ossec key
    print (
        "[*] We received our new pairing key for OSSEC, closing server connection.")
    data = aescall(secret, data, "decrypt")
    # close socket
    s.close()

    # path variables for OSSEC
    if os.path.isdir("C:\\Program Files (x86)\\ossec-agent"):
        path = "C:\\Program Files (x86)\\ossec-agent"
    if os.path.isdir("C:\\Program Files\\ossec-agent"):
        path = "C:\\Program Files\\ossec-agent"
    if os.path.isdir("/var/ossec/"):
        path = "/var/ossec/"
    if path == "":
        sys.exit()
    print ("[*] Removing any old keys.")
    os.chdir(path)

    if installer == "Windows":
        if os.path.isfile("client.keys"):
            os.remove("client.keys")
        # import the key with the key presented from the server daemon
        filewrite = file(path + "\\client.keys", "w")

    if installer == "Linux":
        if os.path.isfile(path + "/etc/client.keys"):
            os.remove("etc/client.keys")
        filewrite = file(path + "/etc/client.keys", "w")

    data = base64.b64decode(data)
    filewrite.write(data)
    filewrite.close()
    # subprocess.Popen("echo y | manage_agents.exe -i %s" % data,
    # stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
    print ("[*] Successfully imported the new pairing key.")
    print ("[*] Stopping the OSSEC service, just in case its running.")
    # stop the service if it is
    if installer == "Windows":
        subprocess.Popen('net stop "OSSEC HIDS"', stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True).wait()

    if installer == "Linux":
        subprocess.Popen("service ossec stop", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True).wait()

    print ("[*] Modifying ossec.conf to incorporate server host IP address.")
    # make sure we modify the ossec.conf

    if installer == "Windows":
        data = file(path + "\\ossec.conf", "r").read()
        if not "<server-ip>%s</server-ip>" % (host) in data:
            filewrite = file(path + "\\ossec.conf", "a")
            filewrite.write("\n")
            filewrite.write(" <ossec_config>")
            filewrite.write("   <client>")
            filewrite.write("      <server-ip>%s</server-ip>" % (host))
            filewrite.write("   </client>")
            filewrite.write(" </ossec_config>")
            filewrite.close()

    if installer == "Linux":
        data = file(path + "etc/ossec.conf", "r").read()
        if not "<server-ip>%s</server-ip>" % (host) in data:
            filewrite = file(path + "etc/ossec.conf", "a")
            filewrite.write("\n")
            filewrite.write(" <ossec_config>")
            filewrite.write("   <client>")
            filewrite.write("    <server-ip>%s</server-ip>" % (host))
            filewrite.write("   </client>")
            filewrite.write(" </ossec_config>")
            filewrite.close()

    # start the service
    if installer == "Windows":
        subprocess.Popen('net start "OSSEC HIDS"', stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True).wait()

    if installer == "Linux":
        subprocess.Popen("service ossec start", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True).wait()

    print (
        "[*] Finished. Started the OSSEC service. Auto Enrollment for OSSEC is now finished.")


except KeyboardInterrupt:
    print ("Sounds good.. Abording Auto-OSSEC...")
    sys.exit()
except Exception as error:
    print (
        "[*] Something did not complete. Does this system have Internet access?")
    print (error)
