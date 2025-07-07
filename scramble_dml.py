#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Anonymise and obsfucate DML data.
# Replace IP Addresses, MAC Addresses, Hostnames and Usernames
#
# Author: Wes Moskal-Fitzpatrick (Traversys Limited)
#
# Change History
# --------------
# 2021-03-15 : WMF : Created.
#

import sys
import os
import re
import datetime
import json
import logging
import argparse
from io import BytesIO
import random
import hashlib
import string
from faker import Faker
from generate_mac import generate_mac
import ipaddress

def swap(line, regex, sublist):
    matching = re.search(regex, line)
    if matching:
        matched = matching.groups()
        for match in matched:
            for sub in sublist:
                if match in sub:
                    line = line.replace(match, sub[match])
    return line

def fuzzySwap(line, swaplist):
    for swapvalue in swaplist:
        for old,new in swapvalue.items():
            matches = re.findall(re.escape(old), line, re.IGNORECASE)
            if matches != None:
                for match in matches:
                    line = line.replace(match, new)
    return line

def substitutes(fake, orig, uniques, swaplist):
    if orig not in uniques:
        uniques.append(orig)
        swaplist.append({orig:fake})
    return swaplist, uniques

def findMatch(line, regex):
    matching = re.search(regex, line)
    if matching:
        matched = matching.groups()
        return matched
    else:
        return []

def fileExists(file):
    exists = os.path.isfile(file)
    if not exists:
        msg = "File '%s' does not exist!" % file
        print(msg)
        logger.critical(msg)
        sys.exit(1)

def valid_ip(address):
    try:
        octets = address.split('.')
        valid = [int(o) for o in octets]
        valid = [o for o in valid if o >= 1 and o <= 255]
        return len(octets) == 4 and len(valid) == 4
    except:
        return False

def valid_ipv6(address):
    try:
        ipaddress.ip_address(address)
        return address
    except:
        return None

### Logging Order = Debug > Info > Warning > Error > Critical

logfile = 'generate_dml_%s.log' % ( str(datetime.date.today() ))
logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
logger = logging.getLogger(__name__)

logger.info("Script started.")

### Capture Arguments
file = None

parser = argparse.ArgumentParser(description='Anonymise and obsfucate DML data.\nReplaces IP Addresses, MAC Addresses, Hostnames')
parser.add_argument('-f', '--file', dest='file', type=file, required=True, metavar='DML FILE', help='The DML file for this script.\n')

args = parser.parse_args()
file = args.file

fileExists(file)

ipSwaps = []
macSwaps = []
dnsSwaps = []
hostSwaps = []
userSwaps = []
uniqIPs = []
uniqMACs = []
uniqDNS = []
uniqHosts = []
uniqUsers = []
testDomains = [ 'corp.com', 'corporate.com' ,'corp.uk' ]
envs = [ 'p','d', 't', 'prod', 'dev', 'test' ]
reserved = [ '127.0.0.1', '255.255.255.255', '0.0.0.0', '255.255.255.0' ]
genericUsers = [ 'NT AUTHORITY\\SYSTEM',
                 'NT AUTHORITY\\NETWORK SERVICE',
                 'NT Authority\\LocalService',
                 'tideway',
                 'tomcat',
                 'root',
                 'LocalSystem' ]

newDML = open("scrambled.dml","w")
usernameFile = open("usernames.log","w")

wc = len(open(file).readlines())
print("No. of lines in file: %i" % wc)
if float(wc) > 500000:
    print("Warning: This may take a while...")

# Setup Value Swaps
with open(file, 'r') as f:
    c = 0
    for line in f.readlines():
        c += 1
        pc = (float(c) / float(wc))
        print('Processing: line %s (%d%%)' % (c,100.0 * pc),end='\r')

        ipAddrs = findMatch(line, "[^\d](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\d]")
        for ipAddr in ipAddrs:
            if ipAddr not in reserved:
                if valid_ip(ipAddr):
                    fakeIP = Faker()
                    fakeIpv4 = fakeIP.ipv4()
                    ipSwaps, uniqIPs = substitutes(fakeIpv4, ipAddr, uniqIPs, ipSwaps)
        ipv6Addrs = findMatch(line, "(([0-9a-fA-F]{0,4}:)+[0-9a-fA-F]{1,4})")
        for ipv6Addr in ipv6Addrs:
            if valid_ipv6(ipv6Addr):
                fakeIP = Faker()
                fakeIpv6 = fakeIP.ipv6()
                ipSwaps, uniqIPs = substitutes(fakeIpv6, ipv6Addr, uniqIPs, ipSwaps)
        macAddrs = findMatch(line, "(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")
        for macAddr in macAddrs:
            if macAddr:
                fakeMac = generate_mac.total_random()
                macSwaps, uniqMACs = substitutes(fakeMac, macAddr, uniqMACs, macSwaps)
        dnsAttrs = findMatch(line, "attribute\sname=\"dns_domain\">(\S+)<")
        for dnsAttr in dnsAttrs:
            if dnsAttr:
                fakeDNS = random.choice(testDomains)
                dnsSwaps, uniqDNS = substitutes(fakeDNS, dnsAttr, uniqDNS, dnsSwaps)
        hostnames = findMatch(line, "attribute\sname=\"hostname\">(\S+)<")
        for hostname in hostnames:
            if hostname:
                hostHash = hashlib.md5(hostname.encode('utf-8')).hexdigest()[:10]
                fakeHostN = "%s%s-%i" % (hostHash, random.choice(envs), random.randint(1,9))
                hostSwaps, uniqHosts = substitutes(fakeHostN, hostname, uniqHosts, hostSwaps)
        usernames = findMatch(line, "attribute\sname=\"username\">(.+)<")
        username = None
        if username:
            u1 = username.group(1)
            u1.replace('"', '')
            u1.replace("'", "")
            usernames.append(u1)
        for user in usernames:
            if user and user not in genericUsers:
                if user.lower() == "name":
                    # Ignore any false match
                    continue
                userHash = hashlib.md5(user.encode('utf-8')).hexdigest()[:8]
                userSwaps, uniqUsers = substitutes(userHash, user, uniqUsers, userSwaps)

usernameFile.write(str(userSwaps))

print("\n100%")
# Replace Values
with open(file, 'r') as f:
    c = 0
    for line in f.readlines():
        old_line = line
        c += 1
        pc = (float(c) / float(wc))
        # Exact matches
        line = swap(line, "[^\d](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\d]", ipSwaps)
        line = swap(line, "(([0-9a-fA-F]{0,4}:)+[0-9a-fA-F]{1,4})", ipSwaps)
        line = swap(line, "(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", macSwaps)

        # Ignore case/partial string matches
        line = fuzzySwap(line, dnsSwaps)
        line = fuzzySwap(line, hostSwaps)
        usernames = findMatch(line, "attribute\sname=\"username\">(.+)<")
        if usernames:
            username = usernames[0]
            for swapvalue in userSwaps:
                for old,new in swapvalue.items():
                    if old == username:
                        line = re.sub("attribute\sname=\"username\">.+<", "attribute name=\"username\">"+ new + "<", line)
        newDML.write(line)

usernameFile.close()
newDML.close()

logger.info("---End---")
