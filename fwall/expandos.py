import socket
import struct
import fcntl
import math

def get_ifip(ifname):
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	iface = struct.pack("256s",ifname[:15])
	info = fcntl.ioctl(sock.fileno(),0x8915,iface) # SIOCGIFADDR
	sock.close()
	return socket.inet_ntoa(info[20:24])

def get_ifnetmask(ifname):
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	iface = struct.pack("256s",ifname[:15])
	info = fcntl.ioctl(sock.fileno(),0x891b,iface) # SIOCGIFNETMASK
	sock.close()
	return socket.inet_ntoa(info[20:24])

def netmask2cidr(netmask):
	return int(32-math.log(2**32-struct.unpack(">I",socket.inet_aton(netmask))[0],2))


def get_ifnetwork(ifname):
	ip = get_ifip(ifname)
	netmask = get_ifnetmask(ifname)
	net=map(lambda (a,b):int(a)&int(b),zip(ip.split("."),netmask.split(".")))
	return ".".join(map(str,net))+"/"+str(netmask2cidr(netmask))
