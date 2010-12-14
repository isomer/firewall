import pprint
from util import *
import getopt
import re
qos = {}

qdiscid=0
def allocate_qdiscid():
	global qdiscid
	qdiscid+=1
	return qdiscid

filterpref=0
def allocate_filterpref():
	global filterpref
	filterpref+=1
	return filterpref

def id2str(id):
	if id is None:
		return "root"
	queueid,classid = id
	if classid is None:
		return "%i:" % queueid
	return "%i:%i" % id

def allocate_child(id):
	if id is None:
		return (allocate_qdiscid(),None)
	queueid,classid = id
	return (queueid,allocate_qdiscid())

def push_line(lines,line):
	if line!=[]:
		lines.append(line)

def parse_multiline(tokens):
	lines=[]
	line=[]
	while tokens!=[]:
		token=tokens.pop(0)
		if token == ';':
			push_line(lines,line)
			line=[]
		elif token == '{':
			line.append(parse_multiline(tokens))
			push_line(lines, line)
			line=[]
		elif token == '}':
			push_line(lines, line)
			line=[]
			return lines
		else:
			line.append(token)
	push_line(lines, line)
	line = []
	return lines
		

def parse_ingress(iface, tokens):
	ast = parse_multiline(tokens)
	if iface not in qos:
		qos[iface]={"egress" : None, "ingress" : None}
	qos[iface]["ingress"]=ast

def parse_egress(iface, tokens):
	ast = parse_multiline(tokens)
	if iface not in qos:
		qos[iface]={"egress" : None, "ingress" : None}
	qos[iface]["egress"]=ast

actions = {
	"mirred" : [ "ingress", "egress",
			"mirror", "redirect",
			"index=", "dev=" ],
	"police" : [ "rate=", "burst=", "mtu", "peakrate=", "avrate=",
			"overhead=", "linklayer=", "action=" ],
	"skbedit" : [ "queue_mapping=", "priority=", "mark=" ],
	"pedit"  : [ "offset=", "at=","offmask=","shift=", "clear","invert","set","retain" ],
	"nat" : [ "ingress", "egress", "old=","new=" ],
}

queue_options = {
	"htb" : [ "default=", "r2q=" ]
}

class_options = {
	"htb" : [ "rate=", "burst=","mpu=", "overhead=","prio=",
		"slow=","pslot=", "ceil=","cburst=","mtu=","quantum=" ]
}

def parse_action(action,args):
	if action not in actions:
		error("Unknown qos action %r" % action)
	args,more = getopt.gnu_getopt(args,"",actions[action])
	if more != []:
		error("Unknown extra arguments %r" % action)
	args=dict(args)
	print "  action",action,
	for i in actions[action]:
		if "--"+i in args:
			print i,
		elif i[-1]=="=" and "--"+i[:-1] in args:
			print i[:-1],args["--"+i[:-1]],
	print "\\"

ll_protonames = [ 
	"ip", "ipv4", "ipv6", "all", "802.1Q",
	"ppp_sess","ppp_disc",
	"loop","pup","pupat","ip","x25","arp""bpq","ieeepup",
	"ieeepupat","dec","dna_dl","dna_rc","dna_rt", "lat", "diag", "cust",
	"sca","rarp","atalk","ipx","atmmpoa",
	"atmfate","802_3","ax25","802_2","snap","ddcmp", "wan_ppp",
	"ppp_mp","localtalk","can","ppptalk","tr_802_2","mobitex", "control",
	"irda","econet","tipc","aoe", ]

meta_vars=["random",
	"loadavg_1","loadavg_5","loadavg_15",
	# "dev",
	"priority", "protocol", "pkt_type", "pkt_len", "data_len", "mac_len",
	"fwmark",
	"tc_index",
	"rt_classid", "rt_iif", "vlan",
	"sk_family", "sk_state", "sk_reuse", "sk_bind_if", "sk_refcnt",
	"sk_shutdown", "sk_proto", "sk_type", "sk_rcvbuf", "sk_rmem",
	"sk_wmem", "sk_omem", "sk_wmem_queue", "sk_snd_queue",
	"sk_rcv_queue", "sk_err_queue", "sk_fwd_alloc", "sk_sndbuf" ]

def exp_source(args):
	assert args[0] == "source"
	args.pop(0)
	return args[1:],["cmp(u32 at 16 layer network mask 0xFFFFFFFF trans eq %s)" % args[0]]

def exp_destination(args):
	assert args[0] == "destination"
	args.pop(0)
	return args[1:],["cmp(u32 at 12 layer network mask 0xFFFFFFFF trans eq %s)" % args[0]]

def parse_filter_metaid(args):
	if re.match("^[0-9]+$",args[0]):
		return args[1:],[args[0]]
	assert args[0] in meta_vars,args[0]
	ret=[args.pop(0)]
	if args[0] == "shift":
		ret.append(args.pop(0))
		ret.append(args.pop(0))
	if args[0] == "mark":
		ret.append(args.pop(0))
		ret.append(args.pop(0))
	return args,ret

def parse_filter_conditional(args):
	if args[0] == "source":
		return exp_source(args)
	elif args[0] == "destination":
		return exp_destination(args)
	elif args[0] in meta_vars:
		args,ret = parse_filter_metaid(args)
		if args[0]=="<":
			args.pop(0)
			ret.append("lt")
		elif args[0]==">":
			args.pop(0)
			ret.append("gt")
		elif args[0] in ["==","="]:
			args.pop(0)
			ret.append("eq")
		elif args[0] in ["<=",">="]:
			error("Kernel doesn't support <= or >= sorry.")
		else:
			error("Unknown conditional %r" % args[0])
		args,ret2 = parse_filter_metaid(args)
		return args,["meta(",]+ret+ret2+[")"]
	error("Unknown variable %r" % args[0])

def parse_filter_conjunction(args):
	if args==[]:
		return [],["fw"]
	args,lhs = parse_filter_conditional(args)
	while args!=[]:
		if args[0]=="and":
			args,rhs= parse_filter_conditional(args[1:])
			lhs = lhs+["and"]+rhs
		elif args[0]=="or":
			args,rhs= parse_filter_conditional(args[1:])
			lhs = lhs+["or"]+rhs
		else:
			error("Unknown conjuction %r" % args[0])
	return args,["basic","match"]+lhs
		
def parse_filter(args):
	for i in ll_protonames:
		if "--"+i in args:
			args.remove("--"+i)
			print "protocol",i,
			break
	args,exp = parse_filter_conjunction(args)
	if args!=[]:
		error("Unexpected %r at end of line" % args)
	print " ".join(exp),"\\"
		
def cmd_match(iface,args):
	if type(args[-1])!=type([]):
		error("match for %r has no actions" % iface)
	filterpref = allocate_filterpref()
	print " filter add dev %s pref %i" % (iface,filterpref),
	if "--fwmark" in args:
		offset=args.index("--fwmark")
		mark=args[offset+1]
		args=args[:offset]+args[offset+2:]
		print "handle %s" % mark,
	parse_filter(args[:-1])
	for i in args[-1]:
		if i[0] != "action":	
			error("Unknown action command %r in %r" % (i[0],iface))
		parse_action(i[1],i[2:])
	print

def dump_ingress(iface,ingress):
	if ingress is None:
		return
	print "## ingress"
	print "qdisc add dev %s handle ffff: ingress" % iface
	for rule in ingress:
		if rule[0] == "match":
			cmd_match(iface,rule[1:])
		else:
			error("Unknown qos command %r" % rule)

def parse_class(class_type,class_rule):
	args,more = getopt.gnu_getopt(class_rule,"",class_options[class_type])
	args=dict(args)
	print "  %s" % class_type,
	for i in class_options[class_type]:
		if "--"+i in args:
			print i,
		elif i[-1]=="=" and "--"+i[:-1] in args:
			print i[:-1],args["--"+i[:-1]],
	print 

def parse_queue(iface,queue_rule,parent):
	assert queue_rule[0] == "queue"
	queue_rule.pop(0)
	myid = allocate_child(parent)
	print "qdisc add dev %s %s handle %s" % (iface,id2str(parent),id2str(myid)),
	if type(queue_rule[-1])==type([]):
		classes = queue_rule[-1]
		queue_rule=queue_rule[:-1]
	else:
		classes = []
	class_type = queue_rule.pop(0)
	if class_type not in queue_options:
		error("Unknown queue %r" % class_type)
	args,more = getopt.gnu_getopt(queue_rule,"",queue_options[class_type])
	print class_type,
	args=dict(args)
	for i in queue_options[class_type]:
		if "--"+i in args:
			print i,
		elif i[-1]=="=" and "--"+i[:-1] in args:
			print i[:-1],args["--"+i[:-1]],
	print 
	for i in classes:
		classid = allocate_child(myid)
		print " class add dev %s classid %s parent %s \\" % (iface,id2str(classid),id2str(classid))
		parse_class(class_type,i)
		

def dump_egress(iface,egress):
	if egress is None:
		return
	print "## egress"
	if len(egress) != 1:
		error("Wrong number of rules for egress for interface %r" % iface)
	if egress[0][0] != "queue":
		error("Top level of egress for interface %r must be a queue" % iface)
	parse_queue(iface,egress[0],None)

def dump_iface(iface,iface_qos):
	print "# %s" % iface 
	dump_egress(iface,iface_qos["egress"])
	dump_ingress(iface,iface_qos["ingress"])
	print

def dump_qos():
	for iface in qos:
		dump_iface(iface,qos[iface])
