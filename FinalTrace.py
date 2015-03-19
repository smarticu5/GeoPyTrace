__author__ = 'Iain Smart'
# Python Cross-Platform Traceroute
# Code for traceroute adapted from https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your, 28/07/2010
# Also, I don't do serious code comments.

# TODO: Map Line
# TODO: Test on Windows (Done. Doesn't work.)
# TODO: More KML Info
# TODO: First hop information
# TODO: Add a whois lookup
# TODO: Add more sarcastic comments

import os
import time
import socket
import sys
import requests
import argparse

# Global constants
GEOLookup = 'http://ip-api.com/json/'
WHOIS = 'http://whois.domaintools.com/'
if sys.platform == "darwin":
	OS = "osx"
elif sys.platform == "linux2":
	OS = "linux"
elif sys.platform == "win32":
	OS = "windows"
else:
	# If not OSx, Win, or Linux, kill program.
	print "Unsupported OS. Program exiting."
	sys.exit()

def get_args():
	# Arguments from command line
	parser = argparse.ArgumentParser(prog="FinalTrace")

	# Important options
	parser.add_argument('-d', '--destination', default='www.hacksoc.co.uk', type=str, help='Destination to trace to')
	parser.add_argument('-o', '--output', default='Traceroute.kml', type=str, help='File to be used for KML')

	# Packet specific settings
	parser.add_argument('-b', '--bytesize', default=512, type=int, help='Number of bytes to read on the receiving socket')
	parser.add_argument('-p', '--port', default=33464, type=int, help='Port to use for receiving packets')
	parser.add_argument('-t', '--TTL', default=20, type=int, help='Maximum number of hops to target')

	# Program verbosity
	parser.add_argument('--debug', action='store_true', help='Enable Debugging Statements')
	parser.add_argument('-v', '--verbosity', action='store_true', help='Control program verbosity')

	# Actions on completion
	parser.add_argument('-lG', action='store_true', help='Automatically open KML File in Google Maps')
	parser.add_argument('-lE', action='store_true', help='Automatically open KML File in Google Earth')

	arguments = parser.parse_args()
	# Check if destination is hostname or IP
	if not check_ip(arguments.destination):
		if arguments.verbosity:
			pInfo('[Info] Inspection suggests destination is not an IP address')
			pInfo('[Info] Attempting to resolve \'{0}\' to IP address'.format(arguments.destination))

		ip = DNS_Lookup(arguments.destination)
		if arguments.verbosity: pInfo('[Info] {0} resolved successfully to {1}'.format(arguments.destination, ip))
		arguments.destination = ip

	# Check if file specified by -o exists
	try:
		if arguments.verbosity: pInfo('[Info] Checking if file {0} exists'.format(arguments.output))
		outfile = open(arguments.output, 'r')
		if arguments.debug: pDebug('[Debug] File {0} exists'.format(arguments.output))
		outfile.close()
	except IOError:
		pWarn('[Warn] File {0} not found. Attempting to create.'.format(arguments.output))
		try:
			outfile = open(arguments.output, 'w')
			pInfo('[Info] File {0} created'.format(arguments.output))
			outfile.close()
		except IOError:
			pError('[Error] Unable to create file. Exiting.')
			sys.exit()
	if arguments.debug:
		arguments.verbosity = True
		pInfo('[Info] Detected OS: {0}'.format(OS))
	if arguments.verbosity:
		pInfo('''
[Info] Destination:\t{0}
[Info] Byte Size:\t{1}
[Info] Output File:\t{2}
[Info] Port:\t\t{3}
[Info] Max Hops:\t{4}\n'''\
			.format(arguments.destination, arguments.bytesize, arguments.output, arguments.port, arguments.TTL))
	return arguments

# Check if -d parameter is an IP Address
def check_ip(testString):
	octets = testString.split('.') # Split into sections based on '.'
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
		pError('[Error] Unable to resolve hostname. Quitting.')
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
				current_host = "{0} ({1})".format(current_name, current_ip_address)
			else:
				current_host = "*"

			IPAddresses.append(current_ip_address)
			if args.verbosity or args.debug: print "{0}\t{1}".format(TTL, current_host)

			TTL += 1

			if current_ip_address == destination or TTL > args.TTL:
				if TTL > args.TTL:
					pWarn('\n[Warn] Max TTL Exceeded')
				if current_ip_address == destination:
					pInfo('\n[Info] Destination reached')
				break

	except KeyboardInterrupt:
		pWarn('[Warn]Keyboard Interrupt. Exiting Traceroute')
	finally:
		return IPAddresses

# Actual Traceroute for Windows systems
def windowsTraceroute():
	pass

def GEOIPLookup(addresses, arguments):
	prevAddr = '0.0.0.0'
	hopNumber = 1

	pInfo('\n[Info] Beginning GeoIP Lookups')
	if arguments.debug: pDebug('[Debug] Address List: {0}'.format(addresses))
	for address in addresses:
		if arguments.debug: pDebug('[Debug] Current Address: {0}'.format(address))
		moreAddresses = False # Default to nothing else to do. Fail closed, I guess.
		for followingAddress in addresses[hopNumber::]: # To determine if there are any hosts still needing looked up
			if followingAddress != address:
				moreAddresses = True
				break

		if args.verbosity: print 'Hop number:\t{0}'.format(hopNumber)
		if address is None:
			if args.verbosity: pWarn('[Warn] No address for this hop. Attempting to use previous address.')
			if prevAddr == '0.0.0.0':
				if args.verbosity: pWarn('[Warn] No previous address available.')
			else:
				pError('[Error] No information available for this address')
				address = prevAddr

		r = requests.get(GEOLookup + str(address))
		data = r.json()
		KMLWriteLocation(data, hopNumber, args)

		prevAddr = address
		hopNumber += 1

		if moreAddresses is False:
			pInfo('[Info] No more addresses to process')
			pInfo('[Info] GEOIP Lookups completed')
			pInfo('[Info] KML File populated')
			return
def GenKML():
	pass

def KMLWriteLocation(data, hopCount, arguments):
	# Write to file
	writeText = ''
	try:
		if data['status'] == 'success':
			city = str(data['city'])
			country = str(data['country'])
			isp = str(data['isp'])
			lat = str(data['lat'])
			lon = str(data['lon'])
			query = str(data['query'])
			coordinates = '%s, %s' % (lon, lat)
			if arguments.verbosity: print 'Address:\t{0}\nCity:\t\t{1}\nCountry:\t{2}\nISP:\t\t{3}\nLat:\t\t{4}\nLon:\t\t{5}\n'.format(query, city, country, isp, lat, lon)
			try:
				if arguments.debug: pDebug('[Debug] Writing hop details to KML')
				KMLFile = open(arguments.output, 'a')
				writeText = '<Placemark>\n\t<name>{0}</name>\n\t<description>\n\t\tIP Address:\t{1}\n\t\tCountry:\t{2}\n\t\tCity:\t\t{3}\n\t\tISP:\t\t{4}\n\t</description>\n\t<Point>\n\t\t<coordinates>\n\t\t\t{5}\n\t\t</coordinates>\n\t</Point>\n</Placemark>\n'.format(hopCount, query, country, city, isp, coordinates)
				KMLFile.write(writeText)
				KMLFile.close()
			except IOError:
				pError('[Error] Cannot open file. Even though this program created it. Did you delete it deliberately?')
				pError('[Error] Exiting program.')
				sys.exit()
			except NameError:
				pError('[Error] You should only see this error if the programmer cocked up. If you see it, I owe you a beer.')
				if args.debug: pError('[Error] And no, reading it in source doesn\'t count. Nice try.')
				sys.exit()
		else:
			pError('[Error] No information available for this hop\n')
	except IOError:
		pError('[Error] IOError: File \'{0}\' cannot be found. Even though this program created it, so stop messing with me.'.format(arguments.output))
	except KeyError:
		pError('[Error] Unexpected Keyerror. Wut?')

def pInfo(printString):
	printString = printString.replace('[Info]', '[{0}Info{1}]')
	print printString.format(bcolors.OKGREEN, bcolors.ENDC)

def pDebug(printString):
	printString = printString.replace('[Debug]', '[{0}Debug{1}]')
	print printString.format(bcolors.OKBLUE, bcolors.ENDC)

def pWarn(printString):
	printString = printString.replace('[Warn]', '[{0}Warn{1}]')
	print printString.format(bcolors.WARNING, bcolors.ENDC)

def pError(printString):
	printString = printString.replace('[Error]', '[{0}Error{1}]')
	print printString.format(bcolors.FAIL, bcolors.ENDC)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
	if OS != "windows" and not os.getuid() == 0:
		pError('[Error] You do not have the required privileges to run this program.')
		sys.exit()
	# Get arguments from command line
	args = get_args()

	# Initialise KML File
	try:
		outfile = open(args.output, 'w')
		outfile.write('<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://earth.google.com/kml/2.0">\n<Document>')
		outfile.close()
		if args.debug: pDebug('[Debug] KML File initialised')
	except IOError:
		pError('[Error] Cannot open file. Even though this program created it. Did you delete it deliberately?')
		pError('[Error] Exiting program.')
		sys.exit()

	# Perform system-specific Traceroute
	if OS == "windows":
		pInfo('[Info] Performing Windows Traceroute')
		IPAddresses = []
		pass # Go do Windows Traceroute
	else:
		pInfo('[Info] Performing *nix Traceroute')
		IPAddresses = nixTraceroute(args)

	# Perform GEOLocation
	GEOIPLookup(IPAddresses, args) # TODO: Error catching on empty list

	# Finalise KML File
	try:
		outfile = open(args.output, 'a')
		outfile.write('</Document>\n</kml>')
		outfile.close()
		if args.verbosity: pInfo('[Info] KML File finalised')
	except IOError:
		pError('[Error] Cannot open file. Even though this program created it. Did you delete it deliberately?')
		pError('[Error] Exiting program.')
		sys.exit()

	# Open any external programs specified
	if args.lE:
		pInfo('[Info] Opening KML in Google Earth')
		if OS == "windows":
			os.system("start {0}".format(args.output))
		elif OS == "osx":
			os.system("open -a '/applications/Google Earth.app' {0}".format(args.output))
		elif OS == "linux":
			os.system("xdg-open {0}".format(args.output))

	# TODO: Open Maps