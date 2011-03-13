import socket
import struct
import fcntl
import math
import os
import shlex

MATCHES_DIR="matches"

loaded_expandos={}

def get_ifip(ifname):
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	iface = struct.pack("256s",ifname[:15])
	try:
		info = fcntl.ioctl(sock.fileno(),0x8915,iface) # SIOCGIFADDR
	except:
		print "Unable to get IP for interface",iface
		raise
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

def load_match(name):
	if os.path.exists(os.path.join(MATCHES_DIR,name+".match")):
		f=open(os.path.join(MATCHES_DIR,name+".match"),"r")
	elif os.path.exists(os.path.join(MATCHES_DIR,name+".smatch")):
		f=os.popen(os.path.join(MATCHES_DIR,name+".smatch"),"r")
	else:
		error("Unknown match %r" % name)
	ret=[]
	for line in f:
		words=shlex.split(line,comments=True)
		if words==[]:
			continue
		if words[0]=="match":
			ret.append(words[1:])	
		else:
			error("Unknown config option %r in match %r" %
				(words[0],name))
	return ret

def compile_match(name):
	return load_match(name)

def load_expand_match(name):
	if "." in name:
		object,property = name.split(".",1)
		if property=="network":
			return [[get_ifnetwork(object)]]
	return compile_match(name)

def expand_match(name):
	if name not in loaded_expandos:
		loaded_expandos[name] = load_expand_match(name)
	return loaded_expandos[name]


