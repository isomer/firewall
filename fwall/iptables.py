from util import *
import expandos
import os
import shlex
import re

MATCHES_DIR="matches"

rules={}
loaded_expandos={}

def add_rule(table,chain,rule):
	if table not in rules:
		error("Unknown table %r" % table)
	if chain not in rules[table]:
		error("Unknown chain %r in table %r" % (chain,table))
	rules[table][chain].append(rule)

def add_table(table):
	assert table not in rules
	rules[table]={}

def add_chain(table,chain):
	assert table in rules
	assert chain not in rules[table]
	rules[table][chain]=[]

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

def expand_match(name):
	if "." in name:
		object,property = name.split(".",1)
		if property=="network":
			return [[expandos.get_ifnetwork(object)]]
	if name not in loaded_expandos:
		loaded_expandos[name]=compile_match(name)
	return loaded_expandos[name]

def expand_matches(args):
	if args==[]:
		yield []
		return
	if args[0][0]=="$":
		for i in expand_match(args[0][1:]):
			for j in expand_matches(args[1:]):
				yield i+j
	else:
		for j in expand_matches(args[1:]):
			yield [args[0]]+j

def is_v4(str):
	return re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)$",str)

def is_v6(str):
	return re.match("^[0-9a-f]*:[0-9a-f:]*(/[0-9]+)?$",str)

_address_args = ["-s","--source","-d","--destination"]

def filter_v4(rule):
	v4=False
	for i in _address_args:
		if i in rule:
			arg=rule[rule.index(i)+1]
			#print "found",i,"in",rule,"checking",repr(arg),is_v4(arg)
			if is_v4(arg):
				return True
	return False

def filter_v6(rule):
	v6=False
	for i in _address_args:
		if i in rule:
			if is_v6(rule[rule.index(i)+1]):
				return True
	return False

def extract(filter_to_reject,rules):
	ret={}
	for table in rules:
		ret[table]={}
		for chain in rules[table]:
			ret[table][chain] = [
				rule
				for rule in rules[table][chain]
				if not filter_to_reject(rule)
			]
	return ret

def extract_v4(rules): return extract(filter_v6, rules)
def extract_v6(rules): return extract(filter_v4, rules)

