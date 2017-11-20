#!/usr/bin/python
#
#                                    Auto-OSSEC Server
#
#  This is the server piece to the client/server pair (ossec_client.py). Auto-OSSEC will create a protocol
#  and allow automatic deployment of OSSEC keys through an enterprise. One of the biggest challenges with
#  OSSEC is the key management pieces which auto-ossec tries to solve. When run, this will listen for comms
#  with auto_ossec.py which is the OSSEC client and pass a key request to the client through an AES 
#  encrypted tunnel. Once the exchange completes, auto_ossec will integrate the key and rewrite the conf
#  file for you to incorporate the server IP address. View the README.md for usage and how to effecitvely
#  use auto-ossec. This also works with AlienVault pairing.
#
#  Written by: Dave Kennedy and the Binary Defense Systems (BDS) Team
#  Twitter: @HackingDave, @Binary_Defense
#  Website: https://www.binarydefense.com 
#
#  Recommended: Place this python file under supervisor to ensure health, stability, and service starts.
#
#  Usage: python auto_sever.py  - This will spawn a port listening and wait for connections from auto_ossec.py
#
#  Will listen on port 9654 for an incoming challege
#
#  Python Crypto and Python Pexpect is required - apt-get install python-crypto python-pexpect
#

# needed for python2/3 compatibility
try: import SocketServer as socketserver
except ImportError: import socketserver
from threading import Thread
import subprocess
import sys
import traceback
import base64
import time
import socket
import os

# python2/3 compatibility
try: import _thread as thread
except ImportError: import thread

# check python crypto library
try:
    from Crypto.Cipher import AES

except ImportError:
    print("[!] ERROR: pycryptodome not installed. Run 'python3 -m install pycrypto' to fix.")
    sys.exit()

# check pexpect library
try:
    import pexpect

except ImportError:
    print("[!] ERROR: pexpect not installed. Run 'python3 -m install pexpect' to fix.")
    sys.exit()

# global lock to restart ossec service
global counter
counter = 0

# global lock for queue
global queue_lock
queue_lock = 0

# main service handler for auto_server
class service(socketserver.BaseRequestHandler):
    def handle(self):
        # parse OSSEC hids client certificate
        def parse_client(hostname, ipaddr):
            child = pexpect.spawn("/var/ossec/bin/manage_agents")
            child.timeout=300
            child.expect("Choose your action")
            child.sendline("a")
            child.expect("for the new agent")
            child.sendline(hostname)
            i = child.expect(['IP Address of the new agent', 'already present'])
            # if we haven't already added the hostname
            if i == 0:
                child.sendline(ipaddr)
                child.expect("for the new agent")
                child.sendline("")
                for line in child:
                    try: line = str(line, 'UTF-8')
                    except TypeError: line = str(line) # python2 compatibility
                    # pull id
                    if "[" in line:
                        id = line.replace("[", "").replace("]", "").replace(":", "").rstrip()
                        break

                child.expect("Confirm adding it?")
                child.sendline("y")
                child.sendline("q")
                child.close()
                child = pexpect.spawn("/var/ossec/bin/manage_agents -e %s" % (id))
                child.timeout=300 
                for line in child: key = line.rstrip() # actual key export
                # when no agents are there and one is removed - the agent wont be added properly right away - need to go through the addition again - appears to be an ossec manage bug - going through everything again appears to solve this
                time.sleep(0.5)
                if "Invalid ID" in str(key): return 0
                return key

            # if we have a duplicate hostname
            else:
                child.close()
                child = pexpect.spawn("/var/ossec/bin/manage_agents -l")
                child.timeout=300 
                for line in child:
                    try: line = str(line, 'UTF-8').rstrip()
                    except TypeError: line = str(line).rstrip() # python 2 and 3 compatibility
                    if hostname in line:
                        remove_id = line.split(",")[0].replace("ID: ", "").replace("   ", "").rstrip()
                        break
                child.close()
                time.sleep(0.5)
                child = pexpect.spawn("/var/ossec/bin/manage_agents -r %s" % (remove_id))
                child.timeout=300
                child.expect("manage_agents: Exiting.")
                time.sleep(2)
                child.close()
                time.sleep(1)
                return 0

        def decryptaes(cipher, data, padding):
            result = str(cipher.decrypt(base64.b64decode(data)), 'UTF-8').rstrip(padding)
            return result

        def decryptaes_py2(cipher, data, padding):
            result = cipher.decrypt(base64.b64decode(data)).rstrip(padding)
            return result

        def encryptaes(cipher, data, padding, blocksize):
            # one-liner to sufficiently pad the text to be encrypted
            pad = lambda s: s + (blocksize - len(s) % blocksize) * padding
            try: data1 = str(data, 'UTF-8') #print('d1', data1)
            except TypeError: data1 = str(data)
            data2 = pad(data1) #; print('d2', data2)
            data3 = cipher.encrypt(data2) #; print('d3', data3, type(data3))
            result = base64.b64encode(data3)
            return result

        # main AES encrypt and decrypt function with 32 block size padding
        def aescall(secret, data, format):

            # padding and block size
            PADDING = '{'
            BLOCK_SIZE = 32

            # random value here to randomize builds
            a = 50 * 5

            # generate the cipher
            cipher = AES.new(secret)

            if format == "encrypt":
                aes = encryptaes(cipher, data, PADDING, BLOCK_SIZE)
                return aes

            if format == "decrypt":
                try: aes = decryptaes(cipher, data, PADDING)
                except TypeError: aes = decryptaes_py2(cipher, data, PADDING)
                return str(aes)

        # recommend changing this - if you do, change auto_ossec.py as well - -
        # would recommend this is the default published to git
        secret = "(3j+-sa!333hNA2u3h@*!~h~2&^lk<!B"

        print("Client connected with ", self.client_address)
        try:
            data = self.request.recv(1024)
            if data != "":
                try:
                    data = aescall(secret, data, "decrypt")
                    # if this section clears -we know that it is a legit
                    # request, has been decrypted and we're ready to rock
                    if "BDSOSSEC" in data:
                        # if we are using star IP addresses
                        if "BDSOSSEC*" in data: star = 1
                        else: star = 0

                        # process to restart OSSEC if needed every 10 minutes -
                        # if lock variable is 1 is present then it will trigger a
                        # restart of OSSEC server
                        global counter
                        counter = 1

                        # strip identifier
                        data = data.replace("BDSOSSEC*", "").replace("BDSOSSEC", "")
                        hostname = data

                        # pull the true IP, not the NATed one if they are using VMWare
                        if star == 0: ipaddr = self.client_address[0]
                        else: ipaddr = "0.0.0.0/0"

                        # this will provision the key 
                        def provision_key(hostname, ipaddr):
                            ossec_key = parse_client(hostname, ipaddr)
                            if ossec_key == 0:
                                ossec_key = parse_client(hostname, ipaddr)
                                # run through again for trouble ones - ossec bug looks like - but this is a decent workaround
                                if ossec_key == 0:
                                    ossec_key = parse_client(hostname, ipaddr)

                            print("[*] Provisioned new key for hostname: %s with IP of: %s" % (hostname, ipaddr))
                            try: ossec_key = ossec_key.decode('UTF-8')
                            except: ossec_key = str(ossec_key) # python2 compatibility
                            ossec_key_crypt = aescall(secret, ossec_key, "encrypt")
                            try: ossec_key_crypt = str(ossec_key_crypt, 'UTF-8') 
                            except TypeError: ossec_key_crypt = str(ossec_key_crypt)
                            print("[*] Sending new key to %s: " % (hostname) + str(ossec_key))
                            # if client disconnected dont crash everything
                            try: self.request.send(ossec_key_crypt.encode('UTF-8'))
                            except: pass
                            time.sleep(1)

                        # here if the hostname was already used, we need to
                        # remove it and call it again
                        global queue_lock

                        # if our queue lock is 0
                        if queue_lock == 0:
                            # locking up the queue to process
                            queue_lock = 1
                            provision_key(hostname, ipaddr)
                            time.sleep(0.2)
                            queue_lock = 0

                        # if we aren't ready to provision wait
                        else:
                            # we need to wait until its finished
                            while 1:
                                # sleep 5 seconds and wait for lock
                                time.sleep(5)
                                if queue_lock == 0:
                                    print("Queue is now free, proceeding with current agent additions..")
                                    queue_lock = 1
                                    provision_key(hostname, ipaddr)
                                    time.sleep(0.2)
                                    queue_lock = 0
                                    break

                except Exception as e:
                    print(e)
                    traceback.print_exc(file=sys.stdout)
                    pass

        except Exception as e:
            print(e)
            pass

        print("Pairing complete. Terminating connection to client.")
        self.request.close()

# this waits 5 minutes to check if new ossec agents have been deployed, if
# so it restarts the server
def ossec_monitor():
    while 1:
        time.sleep(300)
        global counter
        if counter == 1:
            # if we dont have any new agents being added at the time
            if queue_lock == 0:
                print("[*] New OSSEC agent added - triggering restart of service to add..")
                subprocess.Popen("service ossec restart", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                counter = 0

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer): pass

print("[*] The auto enrollment OSSEC Server is now listening on 9654")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# set is so that when we cancel out we can reuse port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# bind to all interfaces on port 10900
ThreadedTCPServer.allow_reuse_address = True
t = ThreadedTCPServer(('', 9654), service)

# start the server and listen forever
try:
    # start a threaded counter
    thread.start_new_thread(ossec_monitor, ())
    t.serve_forever()

except KeyboardInterrupt: print("[*] Exiting the automatic enrollment OSSEC daemon")
