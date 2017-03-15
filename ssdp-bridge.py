#!/usr/local/bin/python -b -O
import socket
import select
import struct
import argparse

multicast_addr = "239.255.255.250"
srv_listen_port = 17113

##################################################

class ClientError(Exception):
    pass

class Client:
	challenge = "ssdp-bridge-c++ v0.0.1\n"

	def __init__(self, socket, addr):
		self.socket = socket
		self.addr = addr
		self.connected = False
		self.client_id = ""

	def is_connected(self):
		return self.connected

	def challenge_append(self, data):
		self.client_id += data
		if(len(self.client_id)>=len(Client.challenge)):
			if(self.client_id != Client.challenge):
				raise ClientError(str(self.addr) + ": challenge failed: '" + self.client_id + "'")
			else:
				self.connected = True
				print("accepted connection from " + str(self.addr) + " ('" + self.client_id[:-1] + "')")

##################################################

def recv_all(socket, l):
	data = bytes()
	while(l):
		r = socket.recv(l)
		if(len(r)==0):
			raise ConnectionResetError("it's a goner!")
		l -= len(r)
		data += r
	return data

def handle_connection(sock):
	conn, addr = sock.accept()
	print("Accepting connection from ", addr)
	# send challenge, client must respond with correct version
	data = "ssdp-bridge-python v0.0.1\n".encode("utf-8");
	conn.send(data);
	return Client(conn,addr)

def forward_ssdp_packet(sock, clients):
	data, addr = ssdp_socket.recvfrom(4096) # buffer = 4k
	#print("Received ssdp message from " + str(addr) + ", ("+ str(len(data))+ " bytes)")
	#print("data:", data.decode("utf-8"))
	data = struct.pack("!I",len(data)) + data
	for client in clients:
		#print("forwarding " + str(len(data)) + " bytes to " + str(client.addr))
		client.socket.send(data)
		#print("ok")

def handle_client(client):
	if client.is_connected():
		data = recv_all(client.socket, 4)
		length = struct.unpack("!I", data)[0]
		if(length>4096):
			raise ClientError("invalid length: "+str(length));
		#print("replaying " + str(length) + " bytes from " + str(client.addr))
		data = recv_all(client.socket, length)
		#print("forwarding to ", ssdp_socket)
		#print("data: ", data.decode("utf-8"))
		if args.map is not None and len(args.map) > 0:
			ssdp_message = data.decode("utf-8");
			for replacement in args.map:
				newmsg = ssdp_message.replace(replacement.src, replacement.dst)
				if( ssdp_message != newmsg ):
					print("replacing " + str(replacement))
				ssdp_message = newmsg
			data = str.encode(ssdp_message);
		ssdp_socket.sendto(data, (multicast_addr, 1900))
	else: # challenge response
		data = recv_all(client.socket, 1).decode("utf-8")
		client.challenge_append(data)

##################################################


class replacement_entry:
	def __init__(self, src, dst):
		self.src = src
		self.dst = dst

	def  __str__(self):
		return self.src + " --> " + self.dst

def make_replacement_entry(string):
	return replacement_entry(string[:string.find("=")], string[string.find("=")+1:])

parser = argparse.ArgumentParser()
parser.add_argument('--map', nargs=1, type=make_replacement_entry, required=False, help='specify replacement for LOCATION strings. <source-text>=<replacement-text>')
args = parser.parse_args()

#print("args: ", args)
#for arg in args.map:
#	print("arg: ", arg)

##################################################

# Connect to SSDP multicast domain
ssdp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
ssdp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssdp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
ssdp_socket.bind(('', 1900))
#ssdp_socket.bind((multicast_addr, 1900))
mreq = struct.pack("=4sl", socket.inet_aton(multicast_addr), socket.INADDR_ANY)
ssdp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

##################################################

srv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv_socket.bind(('', srv_listen_port))
srv_socket.listen(1)

##################################################

sockets=[srv_socket, ssdp_socket]
clients=[]
while 1: # wait for a client
	try:
		#if(len(sockets)<3):
			#print("Waiting for client, listening on port ", srv_listen_port, "...")
		readable, writable, exceptional = select.select(sockets, [], [], 1.0)
#		print("readble: ", readable)
		for sock in readable:
			#print("sock: ", sock)
			if sock is srv_socket:
				client = handle_connection(sock)
				sockets.append(client.socket)
				clients.append(client)
			elif sock is ssdp_socket:
				forward_ssdp_packet(sock, clients)
			else:
				client = clients[sockets.index(sock)-2]
				try:
					handle_client(client)
				except (ConnectionResetError, ClientError) as err:
					print("Dropping connection to " + str(client.addr) + ": " + str(err))
					client.socket.close();
					sockets.remove(client.socket)
					clients.remove(client)
	except KeyboardInterrupt:
		print("KeyboardInterrupt received, exiting...")
		break

for sock in sockets:
	sock.close()
