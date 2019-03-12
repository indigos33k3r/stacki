import struct
import socket
import pytest
from stack import api
from random import randint

pxe_networks = [net['network'] for net in api.Call('list network', args=['pxe=true'])]
interfaces = api.Call('list.host.interface', args=['a:frontend']) 
pxe_interfaces = [inter['interface'] for inter in interfaces if inter['network'] in pxe_networks]


class DHCPPacket:
	def __init__(self):
		self.transactionID = b''
		self.mac_addr = b'\00\x26\x9e\x04\x1e\x9b'
		for i in range(4):
			t = randint(0, 255)
			self.transactionID += struct.pack('!B', t)

	def build_packet(self):
		packet = b''
		# Boot Request
		packet += b'\x01'
		# Ethernet
		packet += b'\x01'
		# Hardware address length
		packet += b'\x06'
		# Hops
		packet += b'\x00'
		# Transaction ID
		packet += self.transactionID
		# Seconds elapsed
		packet += b'\x00\x00'
		# Bootp flags set to broadcast
		packet += b'\x80\x00'
		# Client IP
		packet += b'\x00\x00\x00\x00'
		# Your client IP
		packet += b'\x00\x00\x00\x00'
		# Next server IP
		packet += b'\x00\x00\x00\x00'
		# Relay agent IP
		packet += b'\x00\x00\x00\x00'
		# MAC address
		packet += self.mac_addr
		# MAC address padding
		packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		# Blank server name
		packet += b'\x00' * 67
		# Blank boot file name
		packet += b'\x00' * 125
		# Magic DHCP cookie
		packet += b'\x63\x82\x53\x63'
		# Option: DHCP discover message type
		packet += b'\x35\x01\x01'
		# Client identifier
		packet += b'\x3d\x06' + self.mac_addr
		# Parameter Request list
		packet += b'\x37\x03\x03\x01\x06'
		# End Option
		packet += b'\xff'
		return packet


@pytest.mark.parametrize('interface', pxe_interfaces)
def test_other_dhcp_server(interface):
	# Set up socket with passed in interface
	send_dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	send_dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	send_dhcp.setsockopt(socket.SOL_SOCKET, 25, str(interface + '\0').encode('utf-8'))

	# Abort if port 68 is in use
	try:
		send_dhcp.bind(('', 68))

	except OSError:
		send_dhcp.close()
		pytest.skip("Port 68 in use, make sure another service isn't using it.")

	dhcp_discover_packet = DHCPPacket()
	send_dhcp.sendto(dhcp_discover_packet.build_packet(), ('<broadcast>', 67))

	send_dhcp.settimeout(3)

	errors = ''
	
	# For 3 seconds try to get DHCP offer
	try:
		data = send_dhcp.recv(1024)
		send_dhcp.close()
		if data[4:8] == dhcp_discover_packet.transactionID:
			# Get our offered IP
			offer_ip = '.'.join(map(lambda x: str(x), data[16:20]))
			# Get the IP of the dhcp sever
			server_identifier = '.'.join(map(lambda x: str(x), data[245:249]))
			errors = f'On interface {interface}, DHCP server at {server_identifier} has been found offering ip {offer_ip}'

	# If we don't get an offer, there isn't a rogue server on the network
	except socket.timeout:
		assert True

	assert not errors, f'Other DHCP servers have been found: {errors}'

