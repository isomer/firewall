import unittest
import fwall.firewall
import fwall.iptables

class FirewallTest(unittest.TestCase):
	def setUp(self):
		fwall.firewall.create_chains()

	def tearDown(self):
		fwall.iptables.rules = {}

	def testOptimise(self):
		# Make sure all of our overhead gets optimised away in the 
		# null case.
		fwall.firewall.validate_tables(fwall.iptables.rules)
	
		ipv4_rules = fwall.iptables.extract_v4(fwall.iptables.rules)
		ipv6_rules = fwall.iptables.extract_v6(fwall.iptables.rules)

		fwall.firewall.optimise_tables(ipv4_rules)
		fwall.firewall.optimise_tables(ipv6_rules)

		fwall.firewall.validate_tables(ipv4_rules)
		fwall.firewall.validate_tables(ipv6_rules)

		self.assertEquals(ipv4_rules, {
			'filter': {
				'FORWARD': [], 
				'INPUT': [], 
				'OUTPUT': []}, 
			'mangle': {
				'FORWARD': [], 
				'INPUT': [], 
				'OUTPUT': [], 
				'PREROUTING': [], 
				'POSTROUTING': []}, 
			'nat': {
				'OUTPUT': [], 
				'PREROUTING': [], 
				'POSTROUTING': []
			}})

		self.assertFalse('nat' in ipv6_rules,"IPv6 doesn't need nat")
		self.assertEquals(ipv6_rules, {
			'filter': {
				'FORWARD': [], 
				'INPUT': [], 
				'OUTPUT': []}, 
			'mangle': {
				'FORWARD': [], 
				'INPUT': [], 
				'OUTPUT': [], 
				'PREROUTING': [], 
				'POSTROUTING': []}, 
			})

	def testOptimise2(self):
		fwall.iptables.add_rule('filter', 'INPUT', 
			['DROP', '--protocol', 'tcp', '--port', '80'])
		fwall.iptables.add_rule('filter', 'INPUT', 
			['DROP', '--protocol', 'tcp', '--port', '80'])

		ipv4_rules = fwall.iptables.extract_v4(fwall.iptables.rules)
		ipv6_rules = fwall.iptables.extract_v6(fwall.iptables.rules)

		fwall.firewall.optimise_tables(ipv4_rules)
		fwall.firewall.optimise_tables(ipv6_rules)

		fwall.firewall.validate_tables(ipv4_rules)
		fwall.firewall.validate_tables(ipv6_rules)

	def testIPv4vsIPv6(self):
		# Make sure IPv4 rules only make it to the IPv4 tables
		# Make sure IPv6 rules only make it to the IPv6 tables
		# Make sure other rules end up in both.
		fwall.iptables.add_rule('filter', 'INPUT', 
			['DROP', '--source', '0.0.0.0/0'])
		fwall.iptables.add_rule('filter', 'INPUT', 
			['DROP', '--source', '::1/128'])
		fwall.iptables.add_rule('filter', 'INPUT', 
			['DROP', '--protocol', 'tcp'])

		ipv4_rules = fwall.iptables.extract_v4(fwall.iptables.rules)
		ipv6_rules = fwall.iptables.extract_v6(fwall.iptables.rules)

		fwall.firewall.optimise_tables(ipv4_rules)
		fwall.firewall.optimise_tables(ipv6_rules)

		fwall.firewall.validate_tables(ipv4_rules)
		fwall.firewall.validate_tables(ipv6_rules)

		self.assertEquals(ipv4_rules, {
			'filter': {
				'FORWARD': [], 
				'INPUT': [
					[ 'DROP', '--source', '0.0.0.0/0'],
					[ 'DROP', '--protocol', 'tcp'],
					], 
				'OUTPUT': []}, 
			'mangle': {
				'FORWARD': [], 
				'INPUT': [], 
				'OUTPUT': [], 
				'PREROUTING': [], 
				'POSTROUTING': []}, 
			'nat': {
				'OUTPUT': [], 
				'PREROUTING': [], 
				'POSTROUTING': []
			}})

		self.assertEquals(ipv6_rules, {
			'filter': {
				'FORWARD': [], 
				'INPUT': [
					[ 'DROP', '--protocol', 'tcp'],
					[ 'DROP', '--source', '::1/128'],
					], 
				'OUTPUT': []}, 
			'mangle': {
				'FORWARD': [], 
				'INPUT': [], 
				'OUTPUT': [], 
				'PREROUTING': [], 
				'POSTROUTING': []}, 
			})



if __name__ == '__main__':
	unittest.main()
