#!/usr/bin/python

import sys
import os
import time
import shlex
import socket
import fcntl
import struct
import math
import StringIO

from fwall.util import Error,log,error,debug,DEBUG
import fwall.iptables
import fwall.qos
import fwall.expandos

DEBUG=1
OPTIMISE=1


sysctls=[]

def cmd_if4_feature(interface, feature, value):
	sysctls.append(("net.ipv4.conf.%s.%s" % (interface,feature), value))

def cmd_if6_feature(interface, feature, value):
	sysctls.append(("net.ipv6.conf.%s" % (interface,feature), value))

def cmd_neigh4_feature(feature, value):
	sysctls.append(("net.ipv4.neigh.%s.%s" %(interface,feature), value))

def cmd_neigh6_feature(feature, value):
	sysctls.append(("net.ipv6.neigh.%s.%s" %(interface,feature), value))

def cmd_ip4_feature(feature, value):
	sysctls.append(("net.ipv4.ip_%s" % (feature), value))

def cmd_tcp_feature(feature, value):
	sysctls.append(("net.ipv4.tcp_%s" % feature, value))

def cmd_icmp_feature(feature, value):
	sysctls.append(("net.ipv4.icmp_%s" % feature, value))

def cmd_udp_feature(feature, value):
	sysctls.append(("net.ipv4.udp_%s" % feature, value))

def cmd_set(name,value):
	if name in fwall.expandos.loaded_expandos:
		error("Redefinition of expando %s" % name)
	fwall.expandos.loaded_expandos[name]=[value]

def cmd_policy(table,chain,chainmapping,acceptmapping,rule):
	if chain in chainmapping[table]:
		chain=chainmapping[table][chain]
	if rule[0] in acceptmapping[table]:
		rule=[acceptmapping[table][rule[0]]]+rule[1:]
	for i in fwall.iptables.expand_matches(rule):
		fwall.iptables.add_rule(table,chain,i)

def cmd_ruleset(table,chain,chainmapping,acceptmapping,rule):
	name = rule[0]
	if os.path.exists(os.path.join(fwall.iptables.MATCHES_DIR,name+".ruleset")):
		fh = open(os.path.join(fwall.iptables.MATCHES_DIR,name+".ruleset"),"r")
	elif os.path.exists(os.path.join(fwall.iptables.MATCHES_DIR,name+".sruleset")): 
		fh = os.popen(os.path.join(fwall.iptables.MATCHES_DIR,name+".sruleset"),"r")
	else:
		error("Unknown ruleset %r" % name)
	for i in parse_file(fh):
		if i == []:
			continue
		cmd = i.pop(0)
		if cmd=="policy":
			cmd_policy(table,chain,chainmapping,acceptmapping,i)
		else:
			error("Only policy commands allowed in ruleset %r, not %r" % (rule[0],cmd))

def cmd_ingress(iface,args):
	fwall.qos.parse_ingress(iface,args)

def cmd_egress(iface,args):
	fwall.qos.parse_egress(iface,args)


def parse_file(fh):
	lineno=0
	count=0
	words=[]
	for i in fh:
		lineno+=1
		lexer = shlex.shlex(i)
		lexer.infile=fh.name
		lexer.lineno=lineno
		lexer.whitespace_split=True
		lexer.wordchars += "._-"
		line = list(lexer)
		for j in line:
			if j=="{":
				count=count+1
			elif j=="}":
				count=count-1
		if words == []:
			words = line
		else:
			words += [";"]+line
		if count == 0:
			yield words
			words=[]
	if count != 0:
		error("Missing } in %r" % fh.fname)
	if words != []:
		yield words

def parse_rulesfile(fname, ifname, chainmapping, acceptmapping):
	table,chain=None,None
	for i in parse_file(open(fname,"r")):
		if i==[]:
			continue
		cmd = i.pop(0)
		if cmd == "chain":
			try:
				table,chain = i
			except:
				error("Invalid chain command: %r" % " ".join(i))
		elif cmd == 'policy':
			if table not in chainmapping:
				error("Unknown %r table %r" % (ifname,table))
			if chain not in chainmapping[table]:
				error("Unknown %r chain %r in table %r" % (chain,table))
			cmd_policy(table,chain,chainmapping,acceptmapping,i)
		elif cmd == 'ruleset':
			if table not in chainmapping:
				error("Unknown %r table %r" % (ifname,table))
			if chain not in chainmapping[table]:
				error("Unknown %r chain %r in table %r" % (ifname,chain,table))
			cmd_ruleset(table,chain,chainmapping,acceptmapping,i)
		elif cmd == "if4_feature":
			cmd_if4_feature(ifname,i[0],i[1])
		elif cmd == "if6_feature":
			cmd_if6_feature(ifname,i[0],i[1])
		elif cmd == "neigh4_feature":
			cmd_neigh4_feature(ifname,i[0],i[1])
		elif cmd == "neigh6_feature":
			cmd_neigh6_feature(ifname,i[0],i[1])
		elif cmd == "ip4_feature":
			cmd_ip4_feature(i[0],i[1])
		elif cmd == "tcp_feature":
			cmd_tcp_feature(i[0],i[1])
		elif cmd == "icmp_feature":
			cmd_icmp_feature(i[0],i[1])
		elif cmd == "set":
			cmd_set(i[0],i[1:])
		elif cmd == "ingress":
			cmd_ingress(ifname,i[1:])
		elif cmd == "egress":
			cmd_egress(ifname,i[1:])
		else:
			error("Unknown command %r in %r" % (cmd,fname))

def parse_hostfile(fname):
	chain=None
	table=None
	chainmapping = {
		"filter" : {
			"pre-in" : "fw-host-pre-in",
			"post-in" : "fw-host-post-in",
			"pre-forward" : "fw-host-pre-forward",
			"post-forward" : "fw-host-post-forward",
			"pre-out" : "fw-host-pre-output",
			"post-out" : "fw-host-post-output",
		},
		"nat" : {
			"pre-prerouting-in" 	: "fw-host-pre-prerouting-in",
			"post-prerouting-in" 	: "fw-host-post-prerouting-in",
			"pre-postrouting-in"	: "fw-host-pre-postrouting-in",
			"post-postrouting-in"	: "fw-host-post-postrouting-in",
			"pre-out" 		: "fw-host-pre-output",
			"post-out"		: "fw-host-post-output",
		},
		"mangle" : {
			"pre-prerouting-in" 	: "fw-host-pre-prerouting-in",
			"post-prerouting-in" 	: "fw-host-post-prerouting-in",
			"pre-in" 		: "fw-host-pre-in",
			"post-in" 		: "fw-host-post-in",
			"pre-forward" 		: "fw-host-pre-forward",
			"post-forward" 		: "fw-host-post-forward",
			"pre-out" 		: "fw-host-pre-output",
			"post-out" 		: "fw-host-post-output",
			"pre-postrouting-in"	: "fw-host-pre-postrouting-in",
			"post-postrouting-in"	: "fw-host-post-postrouting-in",
		},
	}
	acceptmapping = {
		"filter" : {
			"fw-host-pre-in" 	: "fw-interface-in",
			"fw-host-pre-forward" 	: "fw-interface-forward-in",
			"fw-host-pre-output" 	: "fw-interface-out",
		},
		"nat"	: {
			"fw-host-pre-prerouting-in" : "fw-interface-prerouting-in",
			"fw-host-pre-output" 	: "fw-interface-out",
			"fw-host-pre-postrouting-out" : "fw-interface-postrouting-out",
		},
		"mangle" : {
			"fw-host-pre-prerouting-in" : "fw-interface-prerouting-in",
			"fw-host-pre-in" 	: "fw-interface-in",
			"fw-host-pre-forward" 	: "fw-interface-forward-in",
			"fw-host-pre-output" 	: "fw-interface-out",
			"fw-host-pre-postrouting-out" : "fw-interface-postrouting-out",
		},
	}

	parse_rulesfile(fname,"default",chainmapping,acceptmapping)

def parse_interfacefile(interface):
	chain=None
	table=None
	chainmapping = {
		"filter" : {
			"in" : "fw-%s-in" % interface,
			"out" : "fw-%s-out" % interface,
			"forward-in" : "fw-%s-forward-in" % interface,
			"forward-out" : "fw-%s-forward-out" % interface,
		},
		"nat" : {
			"prerouting-in" : "fw-%s-prerouting-in" % interface,
			"postrouting-out" : "fw-%s-postrouting-out" % interface,
			"out" : "fw-%s-out" % interface,
		},
		"mangle" : {
			"prerouting-in" : "fw-%s-prerouting-in" % interface,
			"in" : "fw-%s-in" % interface,
			"forward-in" : "fw-%s-forward-in" % interface,
			"forward-out" : "fw-%s-forward-out" % interface,
			"out" : "fw-%s-out" % interface,
			"postrouting-out" : "fw-%s-postrouting-out" % interface,
		},
	}
	acceptmapping = {
		"filter" : {
			"fw-%s-in" % interface : "fw-host-post-in",
			"fw-%s-forward-in" % interface : "fw-interface-forward-out",
			"fw-%s-forward-out" % interface : "fw-host-post-forward",
			"fw-%s-out" % interface : "fw-host-post-out",
		},
		"nat" : {
			"fw-%s-prerouting-in" % interface : "fw-host-post-prerouting-in",
			"fw-%s-out" % interface : "fw-host-post-out",
			"fw-%s-postrouting-out" % interface : "fw-host-post-postrouting-out",
		},
		"mangle" : {
			"fw-%s-prerouting-in" % interface : "fw-host-post-prerouting-in",
			"fw-%s-in" % interface : "fw-host-post-in",
			"fw-%s-forward-in" % interface : "fw-interface-forward-out",
			"fw-%s-forward-out" % interface : "fw-host-post-forward",
			"fw-%s-out" % interface : "fw-host-post-out",
			"fw-%s-postrouting-out" % interface : "fw-host-post-postrouting-out",
		},
	}
	fwall.iptables.add_chain("filter","fw-%s-in" % interface)
	fwall.iptables.add_chain("filter","fw-%s-out" % interface)
	fwall.iptables.add_chain("filter","fw-%s-forward-in" % interface)
	fwall.iptables.add_chain("filter","fw-%s-forward-out" % interface)
	fwall.iptables.add_rule("filter","fw-interface-in",
		["fw-%s-in" % interface,"--in-interface",interface])
	fwall.iptables.add_rule("filter","fw-interface-out",
		["fw-%s-out" % interface,"--out-interface",interface])
	fwall.iptables.add_rule("filter","fw-interface-forward-in",
		["fw-%s-forward-in" % interface,"--in-interface",interface])
	fwall.iptables.add_rule("filter","fw-interface-forward-out",
		["fw-%s-forward-out" % interface,"--out-interface",interface])

	fwall.iptables.add_chain("nat","fw-%s-prerouting-in" % interface)
	fwall.iptables.add_chain("nat","fw-%s-postrouting-out" % interface)
	fwall.iptables.add_chain("nat","fw-%s-out" % interface)
	fwall.iptables.add_rule("nat","fw-interface-prerouting-in",
		["fw-%s-prerouting-in" % interface,"--in-interface",interface])
	fwall.iptables.add_rule("nat","fw-interface-postrouting-out",
		["fw-%s-postrouting-out" % interface,"--out-interface",interface])
	fwall.iptables.add_rule("nat","fw-interface-out",
		["fw-%s-out" % interface,"--out-interface",interface])


	fwall.iptables.add_chain("mangle","fw-%s-prerouting-in" % interface)
	fwall.iptables.add_chain("mangle","fw-%s-in" % interface)
	fwall.iptables.add_chain("mangle","fw-%s-forward-in" % interface)
	fwall.iptables.add_chain("mangle","fw-%s-forward-out" % interface)
	fwall.iptables.add_chain("mangle","fw-%s-out" % interface)
	fwall.iptables.add_chain("mangle","fw-%s-postrouting-out" % interface)
	fwall.iptables.add_rule("mangle","fw-interface-prerouting-in",
		["fw-%s-prerouting-in" % interface,"--in-interface",interface])
	fwall.iptables.add_rule("mangle","fw-interface-in",
		["fw-%s-in" % interface,"--in-interface",interface])
	fwall.iptables.add_rule("mangle","fw-interface-forward-in",
		["fw-%s-forward-in" % interface,"--in-interface",interface])
	fwall.iptables.add_rule("mangle","fw-interface-forward-out",
		["fw-%s-forward-out" % interface,"--out-interface",interface])
	fwall.iptables.add_rule("mangle","fw-interface-out",
		["fw-%s-out" % interface,"--out-interface",interface])
	fwall.iptables.add_rule("mangle","fw-interface-postrouting-out",
		["fw-%s-postrouting-out" % interface,"--out-interface",interface])

	parse_rulesfile(os.path.join("interfaces.d",interface+".if"),
		interface,
		chainmapping,
		acceptmapping)

def dump_rules(f,rules):
	f.write("# Generated by Perry's Firewall Script v2.0 at %s\n" % time.asctime())
	for table in rules:
		f.write("*%s\n" % table)
		for chain in rules[table]:
			if chain.upper() == chain: # Doesn't work in turkey
				f.write(":%s DROP [0:0]\n" % chain)
			else:
				f.write(":%s - [0:0]\n" % chain)
		for chain in rules[table]:
			for rule in rules[table][chain]:
				f.write("-A %s --jump %s\n" % (chain," ".join(rule)))
		f.write("COMMIT\n")

def validate_chains(rules,table):
	for chain in rules[table]:
		for rule in rules[table][chain]:
			if rule[0].upper() == rule[0]:
				continue
			if rule[0] not in rules[table]:
				error("Unknown target %s" % rule[0])
	
def validate_tables(rules):
	for table in rules:
		validate_chains(rules,table)

def optimise_singleton_chains(rules,table):
	# Find all the chains that have one singular rule, or empty
	# and remove them.
	change=False
	singleton_chains={}
	for chain in rules[table]:
		if len(rules[table][chain]) <= 1:
			singleton_chains[chain]=rules[table][chain]
	# Replace jumps to those chains, with the rule itself, merging any matches
	for chain in rules[table]:
		newrules=[]
		for rule in rules[table][chain]:
			if rule[0] in singleton_chains:
				if singleton_chains[rule[0]]==[]:
					debug("Replacing %s:%s:%s with %s" % (table,chain,rule,[]))
					change=True
				else:
					
					newrule = singleton_chains[rule[0]][0]+rule[1:]
					debug("Replacing %s:%s:%s with %s" % (table,chain,rule,newrule))
					newrules.append(newrule)
					change=True
			else:
				newrules.append(rule)
		rules[table][chain]=newrules
	# Remove the singleton chain
	for chain in singleton_chains:
		if chain.upper() != chain: # Fails in turkey
			del rules[table][chain]
			change=True
	return change

def find_match_in_rule(match,rule):
	if match not in rule:
		return (),rule
	grouping = tuple(rule[rule.index(match):rule.index(match)+2])
	newrule=rule[:rule.index(match)]+rule[rule.index(match)+2:]
	return grouping,newrule

def optimise_group_by_match(rules,table,chain,group,matches):
	if matches==[]:
		return group
	matchlist,matches = matches[0],matches[1:]
	groups={}
	for rule in group:
		for match in matchlist:
			grouping,newrule = find_match_in_rule(match,rule)
			if grouping is not ():
				grouping=(matchlist[0],)+grouping[1:]
				break
		groups[grouping]=groups.get(grouping,[])+[newrule]
	newgroup=[]
	for k,v in groups.items():
		for rule in optimise_group_by_match(
				rules,
				table,
				chain,
				v,
				matches):
			newgroup.append(list(k)+rule)
	return newgroup
			
def optimise_group(rules,table,chain,group):
	if group==[]:
		return group
	return optimise_group_by_match(rules,table,chain,group,[
		("--source","-s"),
		("--destination","-d"),
		("--protocol","-p"),
		("--source-port","--sport"),
		("--destination-port","--dport")])

def create_groups_from_chains(rules,table):
	opt=False
	for chain in rules[table]:
		group=[]
		newrules=[]
		target=None
		for rule in rules[table][chain]:
			if group==[] or rule[0]==target:
				group.append(rule[1:])
				target=rule[0]
			else:
				newgroup=optimise_group(rules,table,chain,group)
				newrules += [[target]+x for x in newgroup]
				group = [rule[1:]]
				target = rule[0]
		assert target is not None or group==[]
		group = optimise_group(rules,table,chain,group)
		assert target is not None or group==[]
		newrules += [[target]+x for x in group]
		assert(target is not None or newrules==[])
		rules[table][chain] = newrules
	return opt

def optimise_tables(rules):
	for table in rules:
		opt=True
		while opt:
			opt=optimise_singleton_chains(rules,table)
			opt=opt or create_groups_from_chains(rules,table)

def create_chains():
	fwall.iptables.add_table("filter")
	fwall.iptables.add_chain("filter","INPUT")
	fwall.iptables.add_chain("filter","OUTPUT")
	fwall.iptables.add_chain("filter","FORWARD")
	fwall.iptables.add_table("nat")
	fwall.iptables.add_chain("nat","PREROUTING")
	fwall.iptables.add_chain("nat","POSTROUTING")
	fwall.iptables.add_chain("nat","OUTPUT")
	fwall.iptables.add_table("mangle")
	fwall.iptables.add_chain("mangle","PREROUTING")
	fwall.iptables.add_chain("mangle","INPUT")
	fwall.iptables.add_chain("mangle","FORWARD")
	fwall.iptables.add_chain("mangle","OUTPUT")
	fwall.iptables.add_chain("mangle","POSTROUTING")

def create_default_rules():
	fwall.iptables.add_rule("filter","fw-host-pre-in",["fw-interface-in"])
	fwall.iptables.add_rule("filter","fw-interface-in",["fw-host-post-in"])
	fwall.iptables.add_rule("filter","fw-host-pre-forward",["fw-interface-forward-in"])
	fwall.iptables.add_rule("filter","fw-interface-forward-in",["fw-interface-forward-out"])
	fwall.iptables.add_rule("filter","fw-interface-forward-out",["fw-host-post-forward"])
	fwall.iptables.add_rule("filter","fw-host-pre-out",["fw-interface-out"])
	fwall.iptables.add_rule("filter","fw-interface-out",["fw-host-post-out"])

	fwall.iptables.add_rule("nat","fw-host-pre-prerouting-in",["fw-interface-prerouting-in"])
	fwall.iptables.add_rule("nat","fw-interface-prerouting-in",["fw-host-post-prerouting-in"])
	fwall.iptables.add_rule("nat","fw-host-pre-out",["fw-interface-out"])
	fwall.iptables.add_rule("nat","fw-interface-out",["fw-host-post-out"])
	fwall.iptables.add_rule("nat","fw-host-pre-postrouting-out",["fw-interface-postrouting-out"])
	fwall.iptables.add_rule("nat","fw-interface-postrouting-out",["fw-host-post-postrouting-out"])

	fwall.iptables.add_rule("mangle","fw-host-pre-prerouting-in",["fw-interface-prerouting-in"])
	fwall.iptables.add_rule("mangle","fw-interface-prerouting-in",["fw-host-post-prerouting-in"])
	fwall.iptables.add_rule("mangle","fw-host-pre-in",["fw-interface-in"])
	fwall.iptables.add_rule("mangle","fw-interface-in",["fw-host-post-in"])
	fwall.iptables.add_rule("mangle","fw-host-pre-forward",["fw-interface-forward-in"])
	fwall.iptables.add_rule("mangle","fw-interface-forward-in",["fw-interface-forward-out"])
	fwall.iptables.add_rule("mangle","fw-interface-forward-out",["fw-host-post-forward"])
	fwall.iptables.add_rule("mangle","fw-host-pre-out",["fw-interface-out"])
	fwall.iptables.add_rule("mangle","fw-interface-out",["fw-host-post-out"])
	fwall.iptables.add_rule("mangle","fw-host-pre-postrouting-out",["fw-interface-postrouting-out"])
	fwall.iptables.add_rule("mangle","fw-interface-postrouting-out",["fw-host-post-postrouting-out"])
	fwall.iptables.add_chain("filter","fw-host-pre-in")
	fwall.iptables.add_chain("filter","fw-host-pre-forward")
	fwall.iptables.add_chain("filter","fw-host-pre-out")
	fwall.iptables.add_chain("filter","fw-interface-in")
	fwall.iptables.add_chain("filter","fw-interface-forward-in")
	fwall.iptables.add_chain("filter","fw-interface-forward-out")
	fwall.iptables.add_chain("filter","fw-interface-out")
	fwall.iptables.add_chain("filter","fw-host-post-in")
	fwall.iptables.add_chain("filter","fw-host-post-forward")
	fwall.iptables.add_chain("filter","fw-host-post-out")
	fwall.iptables.add_rule("filter","INPUT",["fw-host-pre-in"])
	fwall.iptables.add_rule("filter","OUTPUT",["fw-host-pre-out"])
	fwall.iptables.add_rule("filter","FORWARD",["fw-host-pre-forward"])

	fwall.iptables.add_chain("nat","fw-host-pre-prerouting-in")
	fwall.iptables.add_chain("nat","fw-interface-prerouting-in")
	fwall.iptables.add_chain("nat","fw-host-post-prerouting-in")
	fwall.iptables.add_chain("nat","fw-host-pre-postrouting-out")
	fwall.iptables.add_chain("nat","fw-interface-postrouting-out")
	fwall.iptables.add_chain("nat","fw-host-post-postrouting-out")
	fwall.iptables.add_chain("nat","fw-host-pre-out")
	fwall.iptables.add_chain("nat","fw-interface-out")
	fwall.iptables.add_chain("nat","fw-host-post-out")
	fwall.iptables.add_rule("nat","PREROUTING",["fw-host-pre-prerouting-in"])
	fwall.iptables.add_rule("nat","POSTROUTING",["fw-host-pre-postrouting-out"])
	fwall.iptables.add_rule("nat","OUTPUT",["fw-host-pre-out"])

	fwall.iptables.add_chain("mangle","fw-host-pre-prerouting-in")
	fwall.iptables.add_chain("mangle","fw-interface-prerouting-in")
	fwall.iptables.add_chain("mangle","fw-host-post-prerouting-in")
	fwall.iptables.add_chain("mangle","fw-host-pre-in")
	fwall.iptables.add_chain("mangle","fw-interface-in")
	fwall.iptables.add_chain("mangle","fw-host-post-in")
	fwall.iptables.add_chain("mangle","fw-host-pre-forward")
	fwall.iptables.add_chain("mangle","fw-interface-forward-in")
	fwall.iptables.add_chain("mangle","fw-interface-forward-out")
	fwall.iptables.add_chain("mangle","fw-host-post-forward")
	fwall.iptables.add_chain("mangle","fw-host-pre-out")
	fwall.iptables.add_chain("mangle","fw-interface-out")
	fwall.iptables.add_chain("mangle","fw-host-post-out")
	fwall.iptables.add_chain("mangle","fw-host-pre-postrouting-out")
	fwall.iptables.add_chain("mangle","fw-interface-postrouting-out")
	fwall.iptables.add_chain("mangle","fw-host-post-postrouting-out")
	fwall.iptables.add_rule("mangle","PREROUTING",["fw-host-pre-prerouting-in"])
	fwall.iptables.add_rule("mangle","INPUT",["fw-host-pre-in"])
	fwall.iptables.add_rule("mangle","FORWARD",["fw-host-pre-forward"])
	fwall.iptables.add_rule("mangle","OUTPUT",["fw-host-pre-out"])
	fwall.iptables.add_rule("mangle","POSTROUTING",["fw-host-pre-postrouting-out"])

def add_expandos(argv):
	for i in argv[1:]:
		k,v = i.split('=',1)
		fwall.expandos.loaded_expandos[k]=(
			fwall.expandos.loaded_expandos.get(k,[])+[[v]])

def main(argv):
	# Setup
	add_expandos(argv)

	create_chains()

	try:
		# Read config
		parse_hostfile("interfaces.d/host")
		for i in os.listdir("interfaces.d"):
			if i.startswith(".") or not i.endswith(".if"):
				log("Skipping %s" % i)
				continue
			parse_interfacefile(os.path.splitext(os.path.basename(i))[0])

		# Special end of chain rules
		create_default_rules()

		validate_tables(fwall.iptables.rules)

		ipv4_rules = fwall.iptables.extract_v4(fwall.iptables.rules)
		ipv6_rules = fwall.iptables.extract_v6(fwall.iptables.rules)
		
		if OPTIMISE:
			optimise_tables(ipv4_rules)
			optimise_tables(ipv6_rules)

		ip4tables = StringIO.StringIO()
		ip6tables = StringIO.StringIO()
		dump_rules(ip4tables, ipv4_rules)
		dump_rules(ip6tables, ipv6_rules)
		print "#!/bin/sh"
		print "################################################################"
		print "# Network configuration script generated by Perry's Firewalling Script"
		print "# on %(host)s at %(time)s" % {
			"host" : socket.gethostname(),
			"time" : time.asctime().strip(),
		}
		print "################################################################"
		print
		print "iptables-restore <<EOF"
		sys.stdout.write(ip4tables.getvalue())
		print "EOF"
		print ""
		print "ip6tables-restore <<EOF"
		sys.stdout.write(ip6tables.getvalue())
		print "EOF"
		print
		print "sysctl -p - <<EOF"
		for (k,v) in sysctls:
			print "%s = %s" % (k,v)
		print "EOF"
		print
		# Note, tc doesn't allow for comments, so we grep them out first.
		# Also, convert multiline tc commands into a single line.
		print r"grep -v '^#' |"
		print r" sed -e':l;/\\$/{N;s/\\\n *//;b l' -e'}' |"
		print r" tc -batch <<EOF"
		fwall.qos.dump_qos()
		print "EOF"
	except Error:
		raise

