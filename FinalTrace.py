__author__ = 'Iain Smart'
# Python Cross-Platform Traceroute
# Code for traceroute adapted from https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your, 28/07/2010

# TODO: Map Line
# TODO: Test on Windows (Done. Doesn't work.)
# TODO: More KML Info
# TODO: First hop information
# TOMAYBEDO: Pi Screen Stuff

import os
import time
import socket
import sys
import requests
import argparse

# Global constants
GEOLookup = 'http://ip-api.com/json/'
WHOIS = 'http://whois.domaintools.com/'
if 'nt' in os.name: WINDOWS = True
else: WINDOWS = False

def get_args():
	# Arguments from command line
	parser = argparse.ArgumentParser(prog="FinalTrace")
	parser.add_argument('-b', '--bytesize', default=512, type=int, help='Number of bytes to read on the receiving socket')
	parser.add_argument('-d', '--destination', default='www.hacksoc.co.uk', type=str, help='Destination to trace to')
	parser.add_argument('-o', '--output', default='Traceroute.kml', type=str, help='File to be used for KML')
	parser.add_argument('-p', '--port', default=33464, type=int, help='Port to use for receiving packets')
	parser.add_argument('-t', '--TTL', default=20, type=int, help='Maximum number of hops to target')
	parser.add_argument('-v', '--verbosity', action='store_true', help='Control program verbosity')

	arguments = parser.parse_args()
	if not check_ip(arguments.destination): # If hostname, not IP, has been entered
		if arguments.verbosity: print '[Info] Inspection suggests destination is not an IP address'
		print '[Info] Attempting to resolve \'%s\' to IP address' % arguments.destination

		ip = DNS_Lookup(arguments.destination)
		if arguments.verbosity: print '[Info] %s resolved successfully to %s' % (arguments.destination, ip)
		arguments.destination = ip
	if arguments.verbosity:
		print '[Info] Destination:\t%s' % arguments.destination
		print '[Info] Byte Size:\t%s' % arguments.bytesize
		print '[Info] Output File:\t%s' % arguments.output
		print '[Info] Port:\t\t%s' % arguments.port
		print '[Info] Max Hops:\t%s' % arguments.TTL
		print
	return arguments

# Check if -d parameter is an IP Address
def check_ip(testString):
	octets = testString.split('.')
	# Split into sections based on '.'
	if len(octets) < 4:
		return False # If there aren't 4, it's not an IP
	else:
		for octet in octets:
			if not octet.isdigit():
				return False
			if not 0 <= int(octet) <= 255: # Each number must be 0-255
				return False
	return True

# Attempt DNS Lookup if not an IP already
def DNS_Lookup(hostname):
	try:
		return socket.gethostbyname(hostname)
	except socket.gaierror:
		print '[Error] Unable to resolve hostname. Quitting.'
		sys.exit()

# Actual Traceroute for *nix based systems
def nixTraceroute(arguments):
	byte_size = arguments.bytesize
	port = arguments.port # Can be anything, really.
	icmp = socket.getprotobyname('icmp')
	udp = socket.getprotobyname('udp')
	TTL = 1
	destination = arguments.destination
	IPAddresses = []

	try:
		while True:
			# Set up sending and receiving sockets
			recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) # Using INET not INET6 for simplicity
			recv_socket.settimeout(1) # Stop program hangs. Note: This wasn't in the original code from Oracle.
			send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

			# Set up packet
			send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, TTL)
			# Bind listener
			recv_socket.bind(("", port))

			#Send packet
			send_socket.sendto("", (destination, port))
			current_ip_address = None
			current_name = None

			try:
				_, current_ip_address = recv_socket.recvfrom(byte_size)
				current_ip_address = current_ip_address[0]
				try:
					current_name = socket.gethostbyaddr(current_ip_address)[0]
				except socket.error:
					current_name = '*'
			except socket.error:
				pass
			finally:
				send_socket.close()
				recv_socket.close()

			if current_ip_address is not None:
				current_host = "%s (%s)" % (current_name, current_ip_address)
			else:
				current_host = "*"

			IPAddresses.append(current_ip_address)
			if args.verbosity: print "%d\t%s" % (TTL, current_host)

			TTL += 1

			if current_ip_address == destination or TTL > args.TTL:
				if TTL > args.TTL:
					print '\n[Warn] Max TTL Exceeded'
				if current_ip_address == destination:
					print '\n[Info] Destination reached'
				break

	except KeyboardInterrupt:
		print 'Keyboard Interrupt. Exiting Traceroute'
	finally:
		return IPAddresses

# Actual Traceroute for Windows systems
def windowsTraceroute():
	pass

def GEOIPLookup(addresses, arguments):
	prevAddr = '0.0.0.0'
	hopNumber = 1

	print '\n[Info] Beginning GeoIP Lookups'
	for address in addresses:
		moreAddresses = False
		for followingAddress in addresses[hopNumber::]: # To determine if there are any hosts still needing looked up
			if followingAddress != address:
				moreAddresses = True
				break

		if moreAddresses is False:
			print '[Info] No more addresses to process'
			print '[Info] GEOIP Lookups completed'
			return

		if args.verbosity: print 'Hop number: %s' % hopNumber
		if address is None:
			if args.verbosity: print '[Warn] No address for this hop. Attempting to use previous address.'
			if prevAddr == '0.0.0.0':
				if args.verbosity: print '[Warn] No previous address available.'
			else:
				address = prevAddr

		r = requests.get(GEOLookup + str(address))
		data = r.json()
		KMLWriteLocation(data, hopNumber, args)

		prevAddr = address
		hopNumber = hopNumber + 1

def GenKML():
	pass

def KMLWriteLocation(data, hopCount, arguments):
		# Write to file
	writeText = ''
	try:
		if data['status'] == 'success':
			# KMLFile = open('IP2.kml', 'a')
			city = str(data['city'])
			country = str(data['country'])
			isp = str(data['isp'])
			lat = str(data['lat'])
			lon = str(data['lon'])
			coordinates = '%s, %s' % (lon, lat)
			if arguments.verbosity: print 'City:\t\t%s\nCountry:\t%s\nISP:\t\t%s\nLat:\t\t%s\nLon:\t\t%s\n' % (city, country, isp, lat, lon)
			# writeText = '<Placemark>\n\t<name>%s</name>\n\t<description>\n\t\tIP Address:\t%s\n\t\tCountry:\t%s\n\t\tCity:\t\t%s\n\t\tISP:\t\t%s\n\t</description>\n\t<Point>\n\t\t<coordinates>\n\t\t\t%s\n\t\t</coordinates>\n\t</Point>\n</Placemark>\n' % (hopCount, address, country, city, isp, coordinates)
			# KMLFile.write(writeText)
			# KMLFile.close()
	except IOError:
		print 'IOError: File \'IP2.kml\' cannot be found. Even though this program created it, so stop messing with me.'
	except KeyError:
		print 'Unexpected Keyerror. Wut?'

if __name__ == "__main__":
	print '''
   ___             ___      _____
  / _ \___  ___   / _ \_   /__   \_ __ __ _  ___ ___
 / /_\/ _ \/ _ \ / /_)/ | | |/ /\/ '__/ _` |/ __/ _ \\
/ /_\\\\  __/ (_) / ___/| |_| / /  | | | (_| | (_|  __/
\____/\___|\___/\/     \__, \/   |_|  \__,_|\___\___|
                       |___/
				Iain Smart (1202028)
'''
	# Check for root
	if not WINDOWS and not os.getuid() == 0:
		print '[Error] You do not have the required privileges to run this program.'
		sys.exit()
	# Get arguments from command line
	args = get_args()
	if WINDOWS:
		print '[Info] Performing Windows Traceroute'
		pass # Go do Windows Traceroute
	else:
		print '[Info] Performing *nix Traceroute'
		IPAddresses = nixTraceroute(args)
	GEOIPLookup(IPAddresses, args)