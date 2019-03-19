import struct
import socket
import pytest
import binascii
from stack import api
from random import randint

pxe_networks = [net['network'] for net in api.Call('list network', args=['pxe=true'])]
interfaces = api.Call('list.host.interface', args=['a:frontend'])
pxe_interfaces = [inter['interface'] for inter in interfaces if inter['network'] in pxe_networks]


def build_dhcp_packet():

	# Unique MAC address
	mac = ''.join('%02x'%randint(0,255) for x in range(6))
	mac_address = binascii.unhexlify(mac)

	# Ensure a unique transaction id when a DHCP request
	# is sent back
	transaction_id = b''
	for i in range(4):
		t = randint(0, 255)
		transaction_id += struct.pack('!B', t)
			
	# Build DHCP discover packet in binary form
	packet = dict(
		boot_request =  b'\x01',
		ethernet =  b'\x01',
	 	mac_length = b'\x06',
		hops =  b'\x00',
		trans_id = transaction_id,
		seconds = b'\x00\x00',
	 	bootp_flags = b'\x80\x00',
		client_ip =  b'\x00\x00\x00\x00',
		your_ip =  b'\x00\x00\x00\x00',
		server_ip =  b'\x00\x00\x00\x00',
		relay_ip =  b'\x00\x00\x00\x00',
		mac_addr = mac_address,
		mac_padding =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		server_name = b'\x00' * 67,
		boot_file =  b'\x00' * 125,
		magic_cookie =  b'\x63\x82\x53\x63',
		dhcp_option = b'\x35\x01\x01',
		client_identifier =  b'\x3d\x06' + mac_address,
		parameter_list = b'\x37\x03\x03\x01\x06',
		end_option =  b'\xff'
	)

	return (packet, transaction_id)

# Run test on every interface that is setup for pxe booting
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

	dhcp_discover_packet, trans_id = build_dhcp_packet()

	# Flatten packet info so it can be sent via socket
	packet = b''
	for value in dhcp_discover_packet.values():
		packet += value

	send_dhcp.sendto(packet, ('<broadcast>', 67))

	send_dhcp.settimeout(3)

	errors = ''
	
	# For 3 seconds try to get DHCP offer
	try:
		data = send_dhcp.recv(1024)
		send_dhcp.close()
		# If the transaction id's match, this offer
		# was for us from our original request
		if data[4:8] == trans_id:
			# Get our offered IP
			offer_ip = '.'.join(map(lambda x: str(x), data[16:20]))
			# Get the IP of the dhcp sever
			server_identifier = '.'.join(map(lambda x: str(x), data[245:249]))
			errors = f'On interface {interface}, DHCP server at {server_identifier} has been found offering ip {offer_ip}'

	# If we don't get an offer, there isn't a rogue server on the network
	except socket.timeout:
		assert True

	assert not errors, f'Other DHCP servers have been found: {errors}'

