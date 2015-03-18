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

coordString = ''

# Traceroute
def DNSLookup(dest_hostname):
	# Set up initial requirements
	ip_addresses = []
	try:
		dest_ip_address = socket.gethostbyname(dest_hostname)
		print 'Tracing route to %s' % dest_ip_address
	except:
		print '[%sWarning%s] Unable to resolve host %s. Exiting' % (bcolors.FAIL, bcolors.ENDC, dest_hostname)
		sys.exit(1)
	port = 13378 # Can be anything, really. Unlikely to be used.
	icmp = socket.getprotobyname('icmp')
	udp = socket.getprotobyname('udp')

	max_hops = 30 # for now, at least

	# Set up incrementing TTL Fields, as per Traceroute spec.
	TTL = 1

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
			send_socket.sendto("", (dest_hostname, port))
			current_ip_address = None
			current_name = None

			# Check response address
			try:
				_, current_ip_address = recv_socket.recvfrom(byte_size)
				current_ip_address = current_ip_address[0]
				try:
					current_name = socket.gethostbyaddr(current_ip_address)[0]
				except socket.error:
					current_name = str(current_ip_address) # For if there ain't no name!
			except socket.error:
				pass # No need for better error handling, makes the program look untidy on timeout.
			finally:
				send_socket.close()
				recv_socket.close()

			if current_ip_address is not None: # i.e. hop data is not given
				current_host = "%s (%s)" % (current_name, current_ip_address)
			else: # Some servers can disable responses
				current_host = "*"
			ip_addresses.append(current_ip_address)
			print "%d\t%s" % (TTL, current_host)

			# Increment TTL
			TTL += 1

			if current_ip_address == dest_ip_address or TTL > max_hops:
				print '\n[%sInfo%s] Traceroute complete.\n'
				time.sleep(1)
				break
	except KeyboardInterrupt:
		print '\n[%sWarning%s] Keyboard Interrupt. Exiting traceroute.' % (bcolors.WARNING, bcolors.ENDC)
	finally:
		return ip_addresses

# GEOIP Lookup
def GEOIPLookup(ip_addresses):
	prevAddr = '0.0.0.0'
	i = 1

	print 'Performing GEOIP Lookups and filling KML File\n'

	for address in ip_addresses:
		moreAddresses = False
		for followingAddress in ip_addresses[i::]:
			if followingAddress != address:
				moreAddresses = True

		print 'Hop Number:\t%s' % i
		i += 1
		if address is None and i != 1:
			print '[%sWarning%s] No address for this hop. Using previous address: %s' % (bcolors.WARNING, bcolors.ENDC, prevAddr)
			address = prevAddr
			# TODO: What if it's 1?

		print 'Address:\t%s' % address
		r = requests.get('http://ip-api.com/json/%s' % address)
		data = r.json()
		KMLWriteLocation(data, i, address)
		prevAddr = address

		if moreAddresses is False:
			print '[%sInfo%s] No more addresses to process.' % (bcolors.OKGREEN, bcolors.ENDC)

			return

def KMLWriteLocation(returnedData, hopCount, address):
	# Write to file
	writeText = ''

	try:
		KMLFile = open('IP2.kml', 'a')

		city = str(returnedData['city'])
		country = str(returnedData['country'])
		isp = str(returnedData['isp'])
		lat = str(returnedData['lat'])
		lon = str(returnedData['lon'])
		coordinates = '%s, %s' % (lon, lat)
		print 'City:\t\t%s\nCountry:\t%s\nISP:\t\t%s\nLat:\t\t%s\nLon:\t\t%s\n' % (city, country, isp, lat, lon)

		writeText = '<Placemark>\n\t<name>%s</name>\n\t<description>\n\t\tIP Address:\t%s\n\t\tCountry:\t%s\n\t\tCity:\t\t%s\n\t\tISP:\t\t%s\n\t</description>\n\t<Point>\n\t\t<coordinates>\n\t\t\t%s\n\t\t</coordinates>\n\t</Point>\n</Placemark>\n' % (hopCount, address, country, city, isp, coordinates)

		KMLFile.write(writeText)
		KMLFile.close()

	except IOError:
		print 'IOError: File \'IP2.kml\' cannot be found. Even though this program created it, so stop messing with me.'

	except KeyError:
		if address[:3:] == '10.':
			print '[%sWarning%s] 10.*.*.* is a reserved IP Range. No Info Available.\n' % (bcolors.WARNING, bcolors.ENDC)
		elif address[:7:] == '172.16.':
			print '[%sWarning%s] 172.*.*.* is a reserved IP Range. No Info Available.\n'  % (bcolors.WARNING, bcolors.ENDC)
		elif address[:4:] == '192.':
			print '[%sWarning%s] 192.*.*.* is a reserved IP Range. No Info Available.\n'  % (bcolors.WARNING, bcolors.ENDC)
		elif address[:2:] == '0.':
			print '[%sWarning%s] 0.*.*.* isn\'t a thing. What did you do this time?\n'  % (bcolors.WARNING, bcolors.ENDC)
		else:
			print 'KeyError. Well that was unexpected'

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

def __init__():
	argParser = argparse.ArgumentParser(prog="FinalTrace")
	argParser.add_argument('-d', '--destination', default = 'www.google.com', type = 'str', help = 'Destination host')
	argParser.add_argument('-o', '--output', default = 'IP2.kml', type = 'str', help = 'Output KML File')



	if os.name == 'nt':
		print 'Naw mate!'
	else:
		if not os.geteuid() == 0:
			print '[%sError%s] Script must be run as root.' % (bcolors.FAIL, bcolors.ENDC)
			sys.exit(1)
		hostname = raw_input('Enter a destination: ')
		# hostname = 'hacksocClone'
		ip_addresses = DNSLookup(hostname)
		print '[%sInfo%s] Creating KML File' % (bcolors.OKGREEN, bcolors.ENDC)
		KMLFile = open('IP2.kml', 'w')
		KMLFile.write('<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://earth.google.com/kml/2.0">\n<Document>\n')
		KMLFile.close()
		GEOIPLookup(ip_addresses)
		KMLFile = open('IP2.kml', 'a')
		KMLFile.write('</Document> </kml>')
		KMLFile.close()
		print '[%sInfo%s] KML File Closed' % (bcolors.OKGREEN, bcolors.ENDC)

__init__()