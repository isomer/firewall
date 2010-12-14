import sys

DEBUG=0

class Error(Exception):
	pass

def log(msg):
	sys.stderr.write("%s\n" % msg)

def error(msg):
	sys.stdout.flush()
	sys.stderr.write("%s\n" % msg)
	sys.stderr.flush()
	raise Error(msg)

def debug(msg):
	if DEBUG:
		sys.stderr.write("%s\n" % msg)

