# ssdp-bridge
--------------

* [Overview](#overview)
* [Usage](#usage)
* [Motivation](#motivation)
* [Deficiencies](#deficiencies)
* [References](#references)



# Overview
Ssdp-bridge is a small server/client program which can capture and replay SSDP traffic (UDP multicast packets) over a TCP connection.



# Usage
On one end of the connection, run the Python utility (see [Deficiencies](#deficiencies) below):
```shell
$ python ssdp-bridge.py
Accepting connection from ('123.45.6.7', 12345)
accepted connection from ('123.45.6.7', 12345) ('ssdp-bridge-c++ v0.0.1')
```
On the other end, run the C++ utility:
```shell
$ ./ssdp-bridge 234.5.6.78 12345
connecting to (234.5.6.78:12345)
connected!
```

SSDP messages are now being routed back and forth between the two end points.



# Motivation
Ssdp-bridge was created in order to bridge a MiniDLNA installation running as a Docker container to my home network across a wireless link. The [appliance](http://freenas.org) that is running the docker host offers only two methods of connecting a container to an outside network; bridging or NATing. Both options don't work well.

##### Bridge mode
In bridge mode the container's network will be bridged to the host's network. The container has its own MAC address and configures its own IP address (e.g. it request an address from your router through DHCP). The problem with this set up is that most wireless routers will only allow a single MAC address per wireless link, and will drop packets with an 'unknown' MAC address. In order to make this work you need a router and device that both support (a compatible) form of WDS (a 4-address mode)<sup>[1](#1)</sup>.

##### NAT mode
In NAT mode the container will not appear directly on the external network, but instead it 'share' the hosts' network addresses (IP, MAC). The problem with this set up is that now the container will no longer receive any multicast packets. I'm not sure why this is, it may have something to do with the way that the network is configured, or even an issue with docker itself (see e.g. [here](https://github.com/docker/docker/issues/23659)).

will live in its own 'virtual' network where it will have its own IP address. The NAT layer will translate IP addresses in the headers of packets, technically enabling devices on the outside to talk to the services inside the container. The problem with this set up is that any IP addresses that the service encodes in the transmitted _data_ are not translated.



##### Solution
The solution that I came up with then is to use a small program to capture and replay SSDP packets between the host and the container. This at least allows SSDP discovery packets sent by devices on the network to reach the service(s) running inside of the container, and for responses from inside to container to reach the outside world.

# Design
Currently there are two implementations of ssdp-bridge, an Python implementation and a C++ implementation. The reason for this is that initially I intended for ssdp-bridge to be a two-part solution. The python program would be a server type, to which the C++ client would connect. The reason for developing the server in Python was that I did not (and still don't) have the capability to compile any native applications for FreeBSD, but that there was a python interpreter installed.

During development it became apparent that both the client and server actually shared many similarities. From that observation came the idea to have two implementation of the same program (protocol), one in Python, and one in C++. Each should offer the same functionality, i.e. it should be able to act both as a 'server' and as a client.



# Deficiencies

##### Only tested in one 'direction'
Currently ssdp-bridge is at the 'proof of concept' stage. I'm using it to connect to a MiniDLNA docker image running on my FreeNAS' over a wireless connection. This is working well, however it only works (is only tested) with the FreeNAS host running the Python implementation, and the MiniDLNA container running the C++ implementation. The MiniDLNA container always connects to the host, because the IP address of the host is fixed whereas that of the container is not.

##### Requires program support
I implemented rudimentary support for rewriting the location URL of SSDP packets coming in from the remote end of the bridge in the Python implementation. However, I soon found out that this is quite useles because, in the case MiniDLNA, after discovering eachother via SSDP, the devices will continue to talk to eachother using HTTP over a TCP connection. While this connection itself is still successful, the URLs advertised in the HTTP responses won't pass through ssdp-bridge, and as such won't have the correct external IP. E.g. MiniDLNA would advertise a video URL over HTTP with its internal (NATted) IP, which was not reachable from the network. You can find a patched version of MiniDLNA on [my github page](https://github.com/dgeelen/minidlna). As of this writing it has not been incorporated into the official MiniDLNA source base.

# References
<a name="1"/>1. [Hyper-V and Wireless networking](https://blogs.msdn.microsoft.com/virtual_pc_guy/2015/02/02/hyper-v-and-wireless-networking/)</a><br>
<a name="2"/>2. [The problem with wireless bridging](https://blog.flameeyes.eu/2011/12/the-problem-with-wireless-bridging/)</a><br>
<a name="3"/>3. [Macvlan vs Ipvlan](https://hicu.be/macvlan-vs-ipvlan)</a><br>
<a name="4"/>4. [Client Mode Wireless](https://wiki.openwrt.org/doc/howto/clientmode)



# License
ssdp-bridge does not currently have a license.
