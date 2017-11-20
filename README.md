~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Binary Defense Systems Auto-Enroll for OSSEC
Written by: David Kennedy - Binary Defense
Twitter: @HackingDave @BinaryDefense
Supported Systems: Linux, OS X, Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The auto ossec enrollment will automatically provision OSSEC agents for both Linux and Windows. This is accomplished through a customized protocol
that interfaces with the ossec server and the automatic pairing of the server. 


Descriptions:

auto_server.py - this file contains the server to house the protocol - the port needed for this is 9654. The agents will communicate with the agents to this server script that is running. This server script should be placed in an automatic init script and through watchdog in order to ensure its always running. This script needs to be placed on the OSSEC server itself.

auto_ossec.exe and auto_ossec.py - auto_ossec.exe is to run on Windows, and auto_ossec.py to run on Linux and OS X. When running the tool you will need to issue auto_ossec.exe <ip_address_of_auto_server> - this will be the IP address of the server itself.

auto_ossec.bin - precompiled for Linux with all libraries bundies in (including python-crypto)

Deployment Instructions:

Install OSSEC server on a system. Ensure that auto_server.py is automatically started when reboot occurs, and watchdog in order to ensure its always running. Also ensure no iptables conflict with port 9654 - this port is needed for the two way communication.

Install OSSEC on a Linux or Windows system as an agent. Then run auto_ossec.exe, auto_ossec.bin, or auto_ossec.py with the IP address of the SERVER that is running auto_server.py. This will automatically pair the instances of OSSEC.

NOTE THAT ALL OF THESE NEED TO BE PERFORMED WITH ROOT OR ADMINISTRATIVE LEVEL PERMISSIONS. THIS WILL FAIL IF IT IS NOT INSTALLED WITH ADMIN PRIVS.

Mass Deployment Instructions:

Create a deployment package that first installs the OSSEC binary or tar ball from (http://www.ossec.net/?page_id=19). Once the install completes, run the auto_ossec <server_ip> and you are finished. Services will automatically restart.

Ports Needed: 9654

What the server should look like when you run it in an interactive interface:

Client connected with  ('192.168.170.165', 50662)
[*] Provisioned new key for hostname: STRONGHOLD-WIN8 with IP of: 192.168.170.165
[*] Sending new key to 192.168.170.165: 8zlUouJ7yVOvt06Er8yx1zTchy5VQklfovu4SXW3GX7X8gH5tPIZ1104wvleQoZmJ9Hod++ByQtgNSLrQV7Z7rsRZLhCS9hFxPwRTZu6JC80EUXJ4yuTqFPHf9L2QuDjelP0yUvFFExf0xm7czlmDVH6/VKRdms1nL8+mwC9S81aZ0IOGpZuIMbIwiyeVxyBpctCk0Qd5CHoVZaKpAWTtA==
Pairing complete. Terminating connection to client.

## Linux Automatic Installation

You can now automatically install Linux as part of the auto_ossec.bin and auto_ossec.py installer. If the proper variable is specified, auto_ossec will automatically download OSSEC from the Internet, install it for you as an agent, and configure the server and keypairs for you.

In order to automatically install Linux, run the following command as root/sudo:

./auto_ossec.bin <server_ip> url=urlto/ossec.tar.gz

The server IP address is the IP address of your OSSEC server installation. The url=<site> specifies that you want to automatically install. You can also specify a wildcard for your hostname of the AGENT. To do this you can type:

./auto_ossec.bin <server_ip> 0.0.0.0/0 url=https://bintray.com/artifact/download/ossec/ossec-hids/ossec-hids-2.8.3.tar.gz

This will automatically install OSSEC through the Internet and specify a wildcard for the IP address of the agent. This is useful when installing agents on dynamic IP addresses.

## Regular Linux Installation

If you install OSSEC regularly on Linux, you can just install OSSEC normally on Linux. Be sure to specify the right server IP address of where your OSSEC server is at and the IP address of where auto_server.py is running (the server enroller).

./auto_ossec.bin <server_ip>

For the Python version, use:

pip3 install -r requirements.txt

This will install python-crypto (for AES support) and pexpect.

Then:

python auto_ossec.py <server_ip>

## Install on Windows

For Windows, install OSSEC normally - since it is an MSI you should install this silently. Once OSSEC is installed, run:

auto_ossec.exe <server_ip>

This will automatically update your OSSEC config file with the server IP address and do the magic needed to pair them. You can also use a 0.0.0.0/0 (wildcard):

auto_ossec.exe <server_ip> 0.0.0.0/0

This will be useful if your system changes IP addresses frequently (dynamic DNS)

## Compile on Windows (auto_ossec.py)

If you want to compile your own auto_ossec.py (instead of the auto_ossec.exe provided), follow the steps below on Windows

1. Download http://aka.ms/vcpython2 (Microsoft Visual C++ 9.0 for Python)
2. Download and Install: https://www.microsoft.com/en-us/download/details.aspx?id=5555
3. Download pyinstaller.org (latest version)
4. Download Python and Install (python.org)
5. Open up a command prompt, type: PATH=C:\Python27 (or 2 or 3 whatever)
6. python -m easy_install pycrypto
7. Unzip pyinstaller, navigate to the directory and type python pyinstaller --onefile auto_ossec.py - this will generate a binary under auto_ossec\dist

## Supported Operating Systems

Linux, OS X, Windows
