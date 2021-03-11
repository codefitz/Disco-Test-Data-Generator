#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Generate a DML file for use in BMC Discovery for generating Playback data
#
# Author: Wes Moskal-Fitzpatrick (Traversys Limited)
#
# Change History
# --------------
# 2020-12-19 : WMF : Created.
#

import sys
import os
import re
import datetime
import json
import logging
import argparse
import ipaddress
from lxml import etree, objectify
from io import BytesIO
import random
from generate_mac import generate_mac
import hashlib
import string
from faker import Faker

### Logging Order = Debug > Info > Warning > Error > Critical

logfile = 'generate_dml_%s.log' % ( str(datetime.date.today() ))
logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger(__name__)

def randomLetter():
    chars = string.ascii_letters
    total = len(chars)
    randomPick = random.randint(0, total - 1)
    letter = chars[randomPick]
    return letter

def makeSerial(count):
    allChars = string.ascii_letters + string.digits
    # print(all_chars)
    charsCount = len(allChars)
    # print(chars_count)
    serials = []
    while count > 0:
        randomNum = random.randint(0, charsCount - 1)
        randomChar = allChars[randomNum]
        serials.append(randomChar)
        count -= 1
    serial = "".join(serials)
    return serial

def fileExists(file):
    exists = os.path.isfile(file)
    if not exists:
        msg = "Ficonnectionsle '%s' does not exist!" % file
        print(msg)
        logger.critical(msg)
        sys.exit(1)

def prettyPrint(jsonData):
    prettyJSON = json.dumps(jsonData, indent=4)
    print (prettyJSON)

def addAttribute(parent, value, attr, attr_value):
    if value:
        parent.append(objectify.Element("attribute"))
        parent.attribute[-1]=value
        parent.attribute[-1].set(attr, attr_value)
        #print(parent.getchildren())
    else:
        host = parent.getparent().endpoint
        #print ("%s attribute %s is null" % (host, attr_value))
        logger.warning("%s: %s attribute '%s' is null" % (host, parent.tag, attr_value))

def addAttributes(endpoint, parent, value, attrs):
    if value:
        parent.append(objectify.Element("attribute"))
        parent.attribute[-1]=value
        for attr, attr_value in attrs.items():
            parent.attribute[-1].set(attr, attr_value)
    else:
        logger.warning("%s: %s attribute '%s' is null" % (endpoint, parent.tag, attrs['name']))

def getAdditionalFile(data, additionalFile, rootElement):
    ### Get ProcessList
    file = data['additional_files'][additionalFile]
    fileExists(file)
    f = open(file,"r")
    jsonData = json.load(f)
    elements = jsonData[rootElement]
    f.close()
    return elements

def generateInterfaces(ipAddr, index, data, os_class, macaddresslist, ipaddresslist):
    if index == 0:
        nic = data['interface_ids'][os_class][0]
    else:
        nic = random.choice(data['interface_ids'][os_class])
    iface = nic + str(index)
    # MAC Address
    mac = generate_mac.total_random()
    macaddresslist.append(objectify.Element("mac_addr"))
    macaddresslist.mac_addr[-1]=mac
    # IP Address
    ipaddressObj = objectify.Element("ipaddress")
    ipaddresslist.append(ipaddressObj)
    workingIP = ipaddress.IPv4Address(ipAddr)
    workingMask = random.choice(data['netmasks'])
    netmask = ipaddress.IPv4Network(ipAddr + '/' + workingMask, False)
    addAttributes(ipAddr, ipaddressObj, ipAddr, {"name":"ip_addr"})
    addAttributes(ipAddr, ipaddressObj, netmask, {"name":"netmask"})
    addAttributes(ipAddr, ipaddressObj, netmask.broadcast_address, {"name":"broadcast"})
    addAttributes(ipAddr, ipaddressObj, "IPv4", {"name":"address_type"})
    addAttributes(ipAddr, ipaddressObj, iface, {"name":"interface_id"})
    addAttributes(ipAddr, ipaddressObj, random.choice(["True","False"]), {"name":"site_local","type":"bool"})
    addAttributes(ipAddr, ipaddressObj, random.choice(["True","False"]), {"name":"link_local","type":"bool"})
    return iface, mac

def generateNIC(networkinterfacelist, ipAddr, iface, mac, index, hostname, hardware_vendor):
    ifaceObj = objectify.Element("networkinterface")
    networkinterfacelist.append(ifaceObj)
    if ipAddr:
        addAttributes(ipAddr, ifaceObj, "%s on %s" % (iface, ipAddr), {"name":"name"})
    else:
        addAttributes(iface, ifaceObj, iface, {"name":"name"})
    addAttributes(ipAddr, ifaceObj, iface, {"name":"interface_id"})
    addAttributes(ipAddr, ifaceObj, mac, {"name":"mac_addr"})
    addAttributes(ipAddr, ifaceObj, index, {"name":"ifindex","type":"int"})
    addAttributes(ipAddr, ifaceObj, random.randint(10,100000), {"name":"speed","type":"int"})
    addAttributes(ipAddr, ifaceObj, random.choice(["AUTO","FORCED",None]), {"name":"negotiation"})
    addAttributes(ipAddr, ifaceObj, random.choice([hostname,None]), {"name":"dns_hostname"})
    addAttributes(ipAddr, ifaceObj, random.choice(["True","False",None]), {"name":"dhcp_enabled"})
    addAttributes(ipAddr, ifaceObj, random.choice([hardware_vendor,None]), {"name":"manufacturer"})

logger.info("Script started.")

### Capture Arguments
argv = sys.argv[1:] # Additional Args
file = None

parser = argparse.ArgumentParser(description='Generate a DML file for use in BMC Discovery for generating Playback data.')
parser.add_argument('-f', '--file', dest='file', type=file, required=True, metavar='JSON_FILE', help='The json input file for this script.\n')

args = parser.parse_args()
file = args.file

fileExists(file)

f = open(file,"r")
endpoints = []
scanRange = []

try:
    data = json.load(f)
    #prettyPrint(data)
except:
    msg = "Problem with JSON!"
    print(msg)
    logger.error(msg)
    sys.exit(1)

### Merge and prep endpoints

for ips in data['endpoints']:
    if 'cidr' in ips:
        net = ipaddress.ip_network(ips['cidr'])
        for addr in net:
            reserved = re.match("\d+\.\d+\.\d+\.(0|255)",str(addr))
            if not reserved:
                endpoints.append(str(addr))
        scanRange.append(ips['cidr']);
    if 'address' in ips:
        endpoints.append(ips['address'])
        scanRange.append(ips['address']);

#print(endpoints)
hosts = data['hosts']

if hosts > len(endpoints):
    msg = "Not enough endpoints specified (%s) for %s hosts!" % (str(len(endpoints)),str(hosts))
    print(msg)
    logger.critical(msg)
    sys.exit(1)

#print("Scan Ranges: " + str(scanRange))

# Mix it up and reduce the list size to the number of hosts wanted
random.shuffle(endpoints)
endpoints = endpoints[:hosts]
#print(len(endpoints))

### Get DDD Lists
endpointList = getAdditionalFile(data, 'endpointHashes','endpoints')
processes = getAdditionalFile(data, 'processes','processes')
commands = getAdditionalFile(data, 'commands','commands')
files = getAdditionalFile(data, 'files','files')
packages = getAdditionalFile(data, 'packages','packages')
patchList = getAdditionalFile(data, 'patches','patches')
registryListings = getAdditionalFile(data, 'registry','registrylisting')
registryValues = getAdditionalFile(data, 'registry','registryvalue')
listeningPorts = getAdditionalFile(data, 'networks','listeningports')
connections = getAdditionalFile(data, 'networks','connections')
wmiQueries = getAdditionalFile(data, 'wmi','wmiquery')
wmiResults = getAdditionalFile(data, 'wmi','wmi')
services = getAdditionalFile(data, 'services','services')
hbas = getAdditionalFile(data, 'hbaOptions','hbas')
directories = getAdditionalFile(data, 'directories','directories')
sqlQueries = getAdditionalFile(data, 'integrations','SQLQueries')
sqlResultRows = getAdditionalFile(data, 'integrations','SQLResultRows')
patternDefines = getAdditionalFile(data, 'integrations','PatternDefines')

### Sort endpointHashes by OS Class
endpointClasses = {}

for endpointItem in endpointList:
    classKey = endpointItem['os_class']
    endpointValue = endpointItem['endpoint']

    # Check for key-value
    if classKey in endpointClasses:
        # append to current key-value
        endpointClasses[classKey].append(endpointValue)
    else:
        # Create new key-value
        endpointClasses[classKey] = [ endpointValue ]

### Sort patches by OS Class
patchOSes = {}

for patchItem in patchList:
    typeKey = patchItem['os_type']
    patchValue = patchItem['patch']

    # Check for key-value
    if typeKey in patchOSes:
        # append to current key-value
        patchOSes[typeKey].append(patchValue)
    else:
        # Create new key-value
        patchOSes[typeKey] = [ patchValue ]

xml = '''<?xml version="1.1" encoding="UTF-8"?>
<demo>
</demo>
'''

root = objectify.fromstring(bytes(xml, encoding='utf8'))
nameBucket = []
randomHostnames = []

for ipAddr in endpoints:

    host = objectify.Element("host")
    deviceinfo = objectify.Element("deviceinfo")
    root.append(host)
    host.endpoint=ipAddr
    host.append(deviceinfo)

    # Kind is Host
    #deviceinfo.append(objectify.Element("attribute"))
    #deviceinfo.attribute[-1] = "Host"
    #deviceinfo.attribute[-1].set("name", "kind")
    addAttribute(deviceinfo, "Host", "name", "kind")

    # Choose Random OS Class
    os_classes = data['os_class']
    os_class = random.choice(os_classes)
    addAttribute(deviceinfo, os_class, "name", "os_class")
    print("OS Class: %s" % os_class)

    # Get Random Endoint Hash
    endpointHash = None
    if os_class in endpointClasses:
        endpointHash = random.choice(endpointClasses[os_class])
        logger.info("%s Using Endpoint Hash: '%s'" % (ipAddr,endpointHash))
        print("%s Using Endpoint Hash: '%s'" % (ipAddr,endpointHash))
    else:
        logger.warning("Was unable to get endpoint hash for %s" % ipAddr)
        continue

    # Choose a Random Platform
    platforms = data['platforms']
    platform = random.choice(data['platforms'][os_class])
    #prettyPrint(platform)
    addAttribute(deviceinfo, platform, "name", "platform")

    # Generate Hostname
    prefix = random.choice(data['hostname_prefixes'])
    type = re.match("^.{3}",str(platform)).group(0)
    env = (re.match("\d+\.\d+\.\d+\.(\d+)",str(ipAddr)))
    if (int(env.group(1)) % 2) == 0:
        env = "p"
    else:
        env = "d"
    hostname = (prefix + type)
    nameBucket.append(hostname)
    nameCnt = nameBucket.count(hostname)
    hostname = (hostname + str(nameCnt) + env).lower()
    addAttribute(deviceinfo, hostname, "name", "hostname")

    # For generating later FS/comms data
    randomHostnames.append(ipAddr)
    randomHostnames.append(hostname)

    # Random Last Access Method
    access_methods = data['access_methods']
    last_access_method = random.choice(data['access_methods'][os_class])
    addAttribute(deviceinfo, last_access_method, "name", "last_access_method")

    # Random Domain Info
    domains = data['domains']
    domain = random.choice(domains)
    addAttribute(deviceinfo, domain, "name", "domain")
    addAttribute(deviceinfo, domain, "name", "dns_domain")
    fqdn = hostname + "." + domain
    addAttribute(deviceinfo, fqdn, "name", "fqdn")

    # Populate OS Info
    os_info = data['os_info']
    os_data = random.choice(data['os_info'][os_class])
    os_ = os_data['os']
    os_arch = os_data['os_arch']
    os_build = os_data['os_build']
    os_edition = os_data['os_edition']
    os_type = os_data['os_type']
    os_vendor = os_data['os_vendor']
    os_version = os_data['os_version']
    device_type = os_data['device_type']
    addAttribute(deviceinfo, os_, "name", "os")
    addAttribute(deviceinfo, os_arch, "name", "os_arch")
    addAttribute(deviceinfo, os_build, "name", "os_build")
    addAttribute(deviceinfo, os_edition, "name", "os_edition")
    addAttribute(deviceinfo, os_type, "name", "os_type")
    addAttribute(deviceinfo, os_vendor, "name", "os_vendor")
    addAttribute(deviceinfo, os_version, "name", "os_version")
    addAttribute(deviceinfo, device_type, "name", "device_type")
    if os_class == "Windows":
        # No idea how this number is generated- but can't generate DML without it.
        addAttributes(ipAddr, deviceinfo, random.randint(100000000000000000,999999999999999999), {"name":"__deviceInfo_via_wmi","type":"int"})

    # Generate HostInfo
    hostinfo = objectify.Element("hostinfo")
    host.append(hostinfo)
    addAttributes(ipAddr, hostinfo, random.choice(data['kernels'][os_class]), {"name":"kernel"})
    hardware_vendor = random.choice(data['hardware_vendors'])
    addAttributes(ipAddr, hostinfo, hardware_vendor, {"name":"vendor"})
    uptimeSeconds = random.randint(100,99999999)
    addAttributes(ipAddr, hostinfo, uptimeSeconds, {"name":"uptimeSeconds","type":"int"})
    addAttributes(ipAddr, hostinfo, uptimeSeconds//86400, {"name":"uptime","type":"int"})
    addAttributes(ipAddr, hostinfo, random.randint(512,256000), {"name":"ram","type":"int"})
    addAttributes(ipAddr, hostinfo, random.randint(512,256000), {"name":"logical_ram","type":"int"})
    addAttributes(ipAddr, hostinfo, random.choice(data['hardware_models']), {"name":"model"})
    addAttributes(ipAddr, hostinfo, random.choice(data['processor_types']), {"name":"processor_type"})
    addAttributes(ipAddr, hostinfo, makeSerial(random.randint(8,22)), {"name":"serial"})
    uuid = "%s-%s-%s-%s-%s" % (makeSerial(8),makeSerial(4),makeSerial(4),makeSerial(4),makeSerial(12))
    addAttributes(ipAddr, hostinfo, uuid.upper(), {"name":"uuid"})
    addAttributes(ipAddr, hostinfo, random.choice([1,2,4,8,16,32,64,128]), {"name":"num_logical_processors","type":"int"})
    addAttributes(ipAddr, hostinfo, random.randint(1800,3200), {"name":"processor_speed","type":"int"})
    addAttributes(ipAddr, hostinfo, datetime.datetime.now()-datetime.timedelta(seconds=uptimeSeconds), {"name":"boot_time","type":"date"})
    addAttributes(ipAddr, hostinfo, random.choice(["True","False"]), {"name":"cpu_threading_enabled","type":"bool"})
    addAttributes(ipAddr, hostinfo, random.choice([1,2,4,8,16]), {"name":"num_processors","type":"int"})
    addAttributes(ipAddr, hostinfo, random.choice([1,2,4]), {"name":"cores_per_processor","type":"int"})
    addAttributes(ipAddr, hostinfo, random.choice([1,2]), {"name":"threads_per_core","type":"int"})

    # UNIX extras
    if os_class == "UNIX":
        __deviceInfo_via_unix_info = random.randint(100000000000000000, 999999999999999999)
        addAttributes(ipAddr, deviceinfo, __deviceInfo_via_unix_info, {"name":"__deviceInfo_via_unix_info","type":"int"})

    # Windows extras
    if os_class == "Windows":
        os_directory = "C:\\Windows"
        addAttribute(deviceinfo, os_directory, "name", "os_directory")
        service_pack = random.choice([ None, 1, 2, 3, 4 ])
        addAttribute(deviceinfo, service_pack, "name", "service_pack")
        if service_pack:
            deviceinfo.attribute[-1].set("type", "int")

    # Generate Mac & IP Addresses
    macaddresslist = objectify.Element("macaddresslist")
    host.append(macaddresslist)
    ipaddresslist = objectify.Element("ipaddresslist")
    host.append(ipaddresslist)
    networkinterfacelist = objectify.Element("networkinterfacelist")
    host.append(networkinterfacelist)

    # Generate the intial IP and MAC (based on scanned endpoint)
    index = 0
    iface, mac = generateInterfaces(ipAddr, index, data, os_class, macaddresslist, ipaddresslist)
    generateNIC(networkinterfacelist, ipAddr, iface, mac, index, hostname, hardware_vendor)

    # Add some random new ones
    for i in range(random.randint(1,9)):
        # Fake IP Address
        fakeIP = Faker()
        fakeIPAddr = fakeIP.ipv4()
        index = i+1
        iface, mac = generateInterfaces(fakeIPAddr, index, data, os_class, macaddresslist, ipaddresslist)
        generateNIC(networkinterfacelist, fakeIPAddr, iface, mac, index, hostname, hardware_vendor)

    # Random Network Interfaces
    for i in range(random.randint(index+1,20)):
        nic = random.choice(data['interface_ids']["Unassigned"])
        iface = nic + str(i)
        generateNIC(networkinterfacelist, None, iface, generate_mac.total_random(), i, hostname, hardware_vendor)

    # FQDNs
    fqdnList = objectify.Element("fqdn")
    host.append(fqdnList)
    addAttributes(ipAddr, fqdnList, ipAddr, {"name":"ip_addr"})

    # Generate NetworkConnectionList
    networkconnectionlist = objectify.Element("networkconnectionlist")
    host.append(networkconnectionlist)
    for listeningPort in listeningPorts:
        if listeningPort['endpoint'] == endpointHash:
            addAttributes(ipAddr, networkconnectionlist, listeningPort['connected_count'], {"name":"connected_count","type":"int"})
            addAttributes(ipAddr, networkconnectionlist, listeningPort['listening_count'], {"name":"listening_count","type":"int"})
            local_ports = listeningPort['local_port']
            if local_ports:
                for i, v in enumerate(local_ports):
                    portObj = objectify.Element("listeningport")
                    networkconnectionlist.append(portObj)
                    localIP = listeningPort['local_ip_addr'][i]
                    if localIP in [ "127.0.0.1", "0.0.0.0", "::", "::1" ]:
                        addAttributes(ipAddr, portObj, localIP, {"name":"local_ip_addr"})
                    else:
                        addAttributes(ipAddr, portObj, ipAddr, {"name":"local_ip_addr"})
                    addAttributes(ipAddr, portObj, local_ports[i], {"name":"local_port","type":"int"})
                    addAttributes(ipAddr, portObj, listeningPort['pid'][i], {"name":"pid","type":"int"})
                    addAttributes(ipAddr, portObj, listeningPort['protocol'][i], {"name":"protocol"})
    for connection in connections:
        if connection['endpoint'] == endpointHash:
            local_ports = connection['local_port']
            if local_ports:
                for i, v in enumerate(local_ports):
                    connectionObj = objectify.Element("networkconnection")
                    networkconnectionlist.append(connectionObj)
                    localIP = connection['local_ip_addr'][i]
                    if localIP in [ "127.0.0.1", "0.0.0.0", "::", "::1" ]:
                        addAttributes(ipAddr, connectionObj, localIP, {"name":"local_ip_addr"})
                    else:
                        addAttributes(ipAddr, connectionObj, ipAddr, {"name":"local_ip_addr"})
                    addAttributes(ipAddr, connectionObj, local_ports[i], {"name":"local_port","type":"int"})
                    addAttributes(ipAddr, connectionObj, connection['remote_ip_addr'][i], {"name":"remote_ip_addr"})
                    addAttributes(ipAddr, connectionObj, connection['remote_port'][i], {"name":"remote_port","type":"int"})
                    addAttributes(ipAddr, connectionObj, connection['protocol'][i], {"name":"protocol"})
                    addAttributes(ipAddr, connectionObj, connection['state'][i], {"name":"state"})
                    addAttributes(ipAddr, connectionObj, connection['pid'][i], {"name":"pid","type":"int"})
                    # TODO : uid: IndexError: string index out of range
                    addAttributes(ipAddr, connectionObj, connection['uid'][i], {"name":"uid","type":"int"})
                    addAttributes(ipAddr, connectionObj, connection['cmd'][i], {"name":"cmd"})

    # Add Package List
    hasPackages = False
    for package in packages:
            if package['endpoint'] == endpointHash and package['name']:
                hasPackages = True
                print("Has Integration Point")
                break

    if hasPackages:
        packagelist = objectify.Element("packagelist")
        host.append(packagelist)
        for package in packages:
                if package['endpoint'] == endpointHash and package['name']:
                    for i, v in enumerate(package['name']):
                        packageObj = objectify.Element("package")
                        packagelist.append(packageObj)
                        addAttributes(ipAddr, packageObj, package['name'][i], {"name":"name"})
                        addAttributes(ipAddr, packageObj, package['version'][i], {"name":"version"})
                        addAttributes(ipAddr, packageObj, package['revision'][i], {"name":"revision"})
                        addAttributes(ipAddr, packageObj, package['description'][i], {"name":"description"})

    # Add Discovered Commands
    for command in commands:
        if command['endpoint'] == endpointHash:
            cmds = command['cmd']
            results = command['result']
            if cmds:
                for i, v in enumerate(cmds):
                    if results[i]:
                        commandObj = objectify.Element("command")
                        host.append(commandObj)
                        addAttributes(ipAddr, commandObj, cmds[i], {"name":"cmd"})
                        addAttributes(ipAddr, commandObj, results[i], {"name":"result"})
                    else:
                        logger.warning("%s: cmd: '%s' had no results." % (ipAddr, cmds[i]))

    # Add Discovered Files
    for file in files:
        if file['endpoint'] == endpointHash:
            paths = file['path']
            modifieds = file['last_modified']
            md5sums = file['md5sum']
            contents = file['content']
            types = file['type']
            permissions_ = file['permissions']
            sizes = file['size']
            groups = file['group']
            owners = file['owner']
            permission_strings = file['permission_string']
            if paths:
                # TODO : Index out of range errors
                for i, v in enumerate(paths):
                    if modifieds:
                        fileObj = objectify.Element("file")
                        host.append(fileObj)
                        addAttributes(ipAddr, fileObj, paths[i], {"name":"path"})
                        addAttributes(ipAddr, fileObj, modifieds[i], {"name":"last_modified"})
                        addAttributes(ipAddr, fileObj, md5sums[i], {"name":"md5sum"})
                        addAttributes(ipAddr, fileObj, contents[i], {"name":"content"})
                        addAttributes(ipAddr, fileObj, permissions_[i], {"name":"permissions"})
                        addAttributes(ipAddr, fileObj, sizes[i], {"name":"size","type":"int"})
                        addAttributes(ipAddr, fileObj, groups[i], {"name":"group"})
                        addAttributes(ipAddr, fileObj, owners[i], {"name":"owner"})
                        addAttributes(ipAddr, fileObj, permission_strings[i], {"name":"permission_string"})

    # Generate Random list of patches
    patches = []
    if os_type in patchOSes:
        #print(len(patchOSes[os_type]))
        patchCount = random.randint(5,1000)
        if len(patchOSes[os_type]) < patchCount:
            patchCount = random.randint(5,len(patchOSes[os_type]))
        patches = random.sample(patchOSes[os_type], patchCount)
        #print(patches)
        if patches:
            checksum = hashlib.md5(repr(patches).encode('utf-8')).hexdigest()
            patcheslist = objectify.Element("patches")
            host.append(patcheslist)
            addAttributes(ipAddr, patcheslist, checksum, {"name":"checksum"})
            addAttributes(ipAddr, patcheslist, str(patches), {"name":"patches","type":"list"})

    # Add RegistryListing, Registry Values
    if os_class == "Windows":
        for reglisting in registryListings:
            if reglisting['endpoint'] == endpointHash:
                query = reglisting['query']
                actual_query = reglisting['actual_query']
                names = reglisting['name']
                keys = reglisting['key_type']
                datas = reglisting['data_type']
                registrylisting = objectify.Element("registrylisting")
                host.append(registrylisting)
                addAttributes(ipAddr, registrylisting, query, {"name":"query"})
                if actual_query:
                    addAttributes(ipAddr, registrylisting, actual_query, {"name":"actual_queries"})
                if (isinstance(names, str)):
                    #print ("names is a string: " + names)
                    entryObj = objectify.Element("registryentry")
                    registrylisting.append(entryObj)
                    addAttributes(ipAddr, entryObj, names, {"name":"name"})
                    addAttributes(ipAddr, entryObj, keys, {"name":"key_type"})
                    addAttributes(ipAddr, entryObj, datas, {"name":"data_type"})
                elif (isinstance(names, list)):
                    #print ("names is a list: %s" % names)
                    for r, v in enumerate(names):
                        #print("name: %s" % v)
                        #print("keys: %s" % keys[r])
                        entryObj = objectify.Element("registryentry")
                        registrylisting.append(entryObj)
                        addAttributes(ipAddr, entryObj, names[r], {"name":"name"})
                        addAttributes(ipAddr, entryObj, keys[r], {"name":"key_type"})
                        addAttributes(ipAddr, entryObj, datas[r], {"name":"data_type"})
        for regvalue in registryValues:
            if regvalue['endpoint'] == endpointHash:
                query = regvalue['query']
                actual_query = regvalue['actual_query']
                value = str(regvalue['value'])
                registryvalue = objectify.Element("registryvalue")
                host.append(registryvalue)
                addAttributes(ipAddr, registryvalue, query, {"name":"query"})
                addAttributes(ipAddr, registryvalue, actual_query, {"name":"actual_query"})
                try:
                    addAttributes(ipAddr, registryvalue, int(value), {"name":"value","type":"int"})
                except:
                    addAttributes(ipAddr, registryvalue, value, {"name":"value"})

    # Add WMI Queries
    if os_class == "Windows":
        for wmiQuery in wmiQueries:
            if wmiQuery['endpoint'] == endpointHash:
                query = wmiQuery['query']
                namespace = wmiQuery['namespace']
                returned_attributes = wmiQuery['returned_attributes']
                wmiqueryObj = objectify.Element("wmiquery")
                host.append(wmiqueryObj)
                addAttributes(ipAddr, wmiqueryObj, query, {"name":"query"})
                addAttributes(ipAddr, wmiqueryObj, namespace, {"name":"namespace"})
                addAttributes(ipAddr, wmiqueryObj, str(returned_attributes), {"name":"returned_attributes","type":"list"})
                if returned_attributes and len(returned_attributes) > 0:
                    for wmi in wmiResults:
                        if wmi['endpoint'] == endpointHash:
                            if wmi['query'] == query:
                                wmiObj = objectify.Element("wmi")
                                wmiqueryObj.append(wmiObj)
                                for i, v in wmi.items():
                                    #print("key: %s, value: %s" %(i,v))
                                    if i not in [ "query", "endpoint" ]:
                                        if v:
                                            try:
                                                addAttributes(ipAddr, wmiObj, int(v), {"name":i,"type":"int"})
                                            except:
                                                if v == "false" or v == "true":
                                                    #print(">>>key, value : %s, %s" % (i,v) )
                                                    addAttributes(ipAddr, wmiObj, str(v).capitalize(), {"name":i,"type":"bool"})
                                                else:
                                                    addAttributes(ipAddr, wmiObj, v, {"name":i})

    # Generate Random Filesystems
    filesystemlist = objectify.Element("filesystemlist")
    host.append(filesystemlist)
    used_mounts = []
    for i in range(random.randint(0,110)):
        file_systems = data['file_systems'][os_class]
        fs_type = random.choice(file_systems['fs_type'])
        if os_class == "UNIX":
            # Standard Generic
            fs_name = "/dev/sda" + str(i)
            fs_mount = random.choice([ "/system", "/tmp", "/opt", "/boot", "/home", "/var", "/usr", "/mnt", "/dev", "/devices", "/data", "/media" ])
            fs_kind = "LOCAL"
            fs_size = random.randint(200000,250000000000)
            fs_serial = None
            if i == 0:
                fs_name = "/dev/sda" + str(i)
                fs_mount = "/"
                fs_size = random.randint(100000,200000000)
            elif fs_type == "cifs":
                fs_name = "//%s/%s" % ( hostname, random.choice([ "shared_" + str(i) ]))
                fs_mount = random.choice([ fs_name, "/shared_" + str(i), None ])
                fs_kind = random.choice([ "REMOTE", "EXPORTED" ])
                fs_size = 0
            elif fs_type == "devtmpfs" or fs_type == "tmpfs":
                fs_name = fs_type
                fs_mount = random.choice([ "/dev", "/run/user" + str(i), "/tmp", "/var/run", "/sys", "/run" ])
                fs_size = random.randint(0,100000000)
            elif fs_type == "proc" or fs_type == "procfs":
                fs_name = fs_type
                fs_mount = "/proc"
                fs_size = 0
            elif fs_type == "vfat":
                fs_name = "/dev/sdb1"
                fs_mount = "/boot/efi"
                fs_size = random.randint(100000,300000)
            elif fs_type == "zfs":
                fs_name = random.choice(["zones", "zones/pool" + str(i), "rpool", "rpool/export" "zones/%s" % random.choice(randomHostnames) ])
                fs_mount = random.choice([ fs_name, "/", "/zones", "/var", "/export", "/ftp" ])
            elif fs_type == "nfs" or fs_type == "nfs3":
                random.choice(randomHostnames)
                source = "%s:" % random.choice(randomHostnames)
                mount = random.choice([ "/vol" + str(i), "/home", "/pub", "/media" ])
                fs_name = random.choice([ source + mount, mount ])
                fs_mount = random.choice([fs_name, mount, "/vol", "/cache", "/home/%s" % random.choice(data['usernames'][os_class]) ])
                fs_kind = random.choice([ "REMOTE", "EXPORTED" ])
                fs_size = 0

        elif os_class == "Windows":
            # Standard Generic
            driveLetter = randomLetter().upper()
            fs_name = "Disk #%s, Partition #%s" % (random.randint(0,30),random.randint(0,2))
            fs_mount = "%s:" % driveLetter
            fs_size = random.randint(200000,250000000000)
            fs_serial = random.choice([ makeSerial(8) ]).upper()
            if i == 0:
                fs_name = "Disk #0, Partition #0"
                fs_mount = "C:"
                fs_kind = "LOCAL"
                fs_size = random.randint(100000,200000000)
            elif fs_type == "cifs":
                random_shares = [ "shared_" + str(i), driveLetter + "$" ]
                fs_name = "\\\\%s\\%s" % ( hostname, random.choice(random_shares))
                fs_mount = random.choice([ fs_name, "\\shared_" + str(i) + "$", driveLetter + "$", None ])
                fs_kind = random.choice([ "REMOTE", "EXPORTED" ])
                fs_size = 0
                fs_serial = None

        if fs_mount in used_mounts:
            # Skip and do-over
            continue
        used_mounts.append(fs_mount)

        filesystem = objectify.Element("filesystem")
        filesystemlist.append(filesystem)
        addAttributes(ipAddr, filesystem, fs_type, {"name":"fs_type"})
        addAttributes(ipAddr, filesystem, random.choice(file_systems['comments']), {"name":"comment"})
        addAttributes(ipAddr, filesystem, fs_name, {"name":"name"})
        addAttributes(ipAddr, filesystem, fs_mount, {"name":"mount"})
        addAttributes(ipAddr, filesystem, fs_kind, {"name":"fs_kind"})
        addAttributes(ipAddr, filesystem, str(fs_size), {"name":"size","type":"int"})
        addAttributes(ipAddr, filesystem, str(random.randint(0,fs_size)), {"name":"used","type":"int"})
        addAttributes(ipAddr, filesystem, fs_serial, {"name":"serial"})

    # Add Directory Listings
    for directory in directories:
        if directory['endpoint'] == endpointHash:
            last_modified = directory['last_modified']
            if directory['last_modified']:
                print("Directories found")
                directorylisting = objectify.Element("directorylisting")
                host.append(directorylisting)
                addAttributes(ipAddr, directorylisting, directory['path'], {"name":"path"})
                for i, v in enumerate(last_modified):
                    directoryentry = objectify.Element("directoryentry")
                    directorylisting.append(directoryentry)
                    addAttributes(ipAddr, directoryentry, directory['name'][i], {"name":"name"})
                    addAttributes(ipAddr, directoryentry, last_modified[i], {"name":"last_modified"})
                    addAttributes(ipAddr, directoryentry, directory['file_type'][i], {"name":"file_type"})
                    addAttributes(ipAddr, directoryentry, directory['mode'][i], {"name":"mode"})
                    addAttributes(ipAddr, directoryentry, directory['minor'][i], {"name":"minor","type":"int"})
                    addAttributes(ipAddr, directoryentry, directory['extra'][i], {"name":"extra"})
                    try:
                        addAttributes(ipAddr, directoryentry, directory['permissions_string'][i], {"name":"permissions_string"})
                    except:
                        pass
                    try:
                        addAttributes(ipAddr, directoryentry, str(directory['permissions'][i]), {"name":"permissions","type":"list"})
                    except:
                        pass
                    try:
                        addAttributes(ipAddr, directoryentry, directory['group'][i], {"name":"group"})
                    except:
                        pass
                    try:
                        addAttributes(ipAddr, directoryentry, str(directory['size'][i]), {"name":"size","type":"int"})
                    except:
                        addAttributes(ipAddr, directoryentry, "0", {"name":"size","type":"int"})
                    try:
                        addAttributes(ipAddr, directoryentry, directory['major'][i], {"name":"major","type":"int"})
                    except:
                        pass
                    try:
                        addAttributes(ipAddr, directoryentry, directory['owner'][i], {"name":"owner"})
                    except:
                        pass

    # Generate HBAs
    if os_class == "Windows":
        for hba in hbas:
            if hba['endpoint'] == endpointHash:
                print("HBA Info")
                hbainfolist = objectify.Element("hbainfolist")
                host.append(hbainfolist)
                roles = hba['role']
                speed = random.randint(0,10000000000)
                port_state = random.choice(["Operational", None])
                port_type = random.choice(["Fabric (N)","Point to Point (PTP)", None])
                model_desc = random.choice(["Fibre Channel Adapter","PCI-Express Dual Channel Fibre Channel HBA"])
                model_name = random.choice(["FBE123","FC678", None])
                driver = random.choice(["fbc000.sys", None])
                for i, v in enumerate(roles):
                    hbaObj = objectify.Element("hba")
                    hbainfolist.append(hbaObj)
                    addAttributes(ipAddr, hbaObj, "Host", {"name":"role"})
                    addAttributes(ipAddr, hbaObj, hba['fabric_name'][i], {"name":"fabric_name"})
                    addAttributes(ipAddr, hbaObj, speed, {"name":"speed","type":"int"})
                    addAttributes(ipAddr, hbaObj, hba['driver_version'][i], {"name":"driver_version"})
                    addAttributes(ipAddr, hbaObj, random.choice(data['hardware_vendors']), {"name":"manufacturer"})
                    addAttributes(ipAddr, hbaObj, hba['WWNN'][i], {"name":"WWNN"})
                    addAttributes(ipAddr, hbaObj, hba['WWPN'][i], {"name":"WWPN"})
                    addAttributes(ipAddr, hbaObj, hba['firmware'][i], {"name":"firmware"})
                    addAttributes(ipAddr, hbaObj, "[2000000000,4000000000,8000000000,10000000000]", {"name":"supported_speeds","type":"list"})
                    addAttributes(ipAddr, hbaObj, hba['boardID'][i], {"name":"boardID"})
                    addAttributes(ipAddr, hbaObj, port_state, {"name":"port_state"})
                    addAttributes(ipAddr, hbaObj, port_type, {"name":"port_type"})
                    addAttributes(ipAddr, hbaObj, model_desc, {"name":"model_description"})
                    addAttributes(ipAddr, hbaObj, model_name, {"name":"model_name"})
                    addAttributes(ipAddr, hbaObj, "[ 'Class 1', 'Class 2', 'Class 3']", {"name":"supported_classes","type":"list"})
                    addAttributes(ipAddr, hbaObj, hba['option_rom_version'][i], {"name":"option_rom_version"})
                    addAttributes(ipAddr, hbaObj, str(makeSerial(13)).upper(), {"name":"serial_number"})
                    addAttributes(ipAddr, hbaObj, driver, {"name":"driver_name"})

    # Add Services
    if os_class == "Windows":
        servicelist = objectify.Element("servicelist")
        host.append(servicelist)
        for service in services:
            if service['endpoint'] == endpointHash:
                names = service['name']
                if names:
                    for i, v in enumerate(names):
                        serviceObj = objectify.Element("service")
                        servicelist.append(serviceObj)
                        username = random.choice(data['usernames'][os_class])
                        addAttributes(ipAddr, serviceObj, username, {"name":"username"})
                        addAttributes(ipAddr, serviceObj, names[i], {"name":"name"})
                        addAttributes(ipAddr, serviceObj, service['state'][i], {"name":"state"})
                        addAttributes(ipAddr, serviceObj, service['display_name'][i], {"name":"display_name"})
                        addAttributes(ipAddr, serviceObj, service['pid'][i], {"name":"pid","type":"int"})
                        addAttributes(ipAddr, serviceObj, service['start_mode'][i], {"name":"start_mode"})
                        addAttributes(ipAddr, serviceObj, service['cmdline'][i], {"name":"cmdline"})

    # Add Process List
    processlist = objectify.Element("processlist")
    host.append(processlist)
    addAttributes(ipAddr, processlist, "True", {"name":"full_cmdline","type":"bool"})

    for process in processes:
        if process['endpoint'] == endpointHash:
            pids = process['pid']
            if pids:
                for i, v in enumerate(pids):
                    processObj = objectify.Element("process")
                    processlist.append(processObj)
                    username = random.choice(data['usernames'][os_class])
                    addAttributes(ipAddr, processObj, username, {"name":"username"})
                    addAttributes(ipAddr, processObj, process['cmd'][i], {"name":"cmd"})
                    addAttributes(ipAddr, processObj, process['args'][i], {"name":"args"})
                    addAttributes(ipAddr, processObj, pids[i], {"name":"pid","type":"int"})
                    addAttributes(ipAddr, processObj, process['ppid'][i], {"name":"ppid","type":"int"})
                    addAttributes(ipAddr, processObj, process['uid'][i], {"name":"uid","type":"int"})
                    if process['suppress_candidate_si'][i]:
                        addAttributes(ipAddr, processObj, str(process['suppress_candidate_si'][i]).capitalize(), {"name":"suppress_candidate_si","type":"bool"})

    # Generate Integrations
    integrationPoint = False
    for sqlQuery in sqlQueries:
        if sqlQuery['endpoint'] == endpointHash:
            integrationPoint = True
            print("Has Integration Point")
            break

    if integrationPoint:
        for sqlQuery in sqlQueries:
            if sqlQuery['endpoint'] == endpointHash:
                provider = objectify.Element("provider")
                host.append(provider)
                provider.set("type", "SQL")
                for sqlQuery in sqlQueries:
                    label = sqlQuery['label']
                    queryHash = sqlQuery['_hash']
                    qryAttributes = sqlQuery['returned_attributes']
                    integrationresult = objectify.Element("integrationresult")
                    provider.append(integrationresult)
                    detailObj = objectify.Element("details")
                    integrationresult.append(detailObj)
                    addAttributes(ipAddr, detailObj, label, {"name":"label"})
                    addAttributes(ipAddr, detailObj, queryHash, {"name":"_hash"})
                    addAttributes(ipAddr, detailObj, sqlQuery['connection_parameter_address'], {"name":"connection_parameter_address"})
                    addAttributes(ipAddr, detailObj, sqlQuery['connection_parameter_database'], {"name":"connection_parameter_database"})
                    addAttributes(ipAddr, detailObj, sqlQuery['connection_parameter_endpoint'], {"name":"connection_parameter_endpoint"})
                    try:
                        addAttributes(ipAddr, detailObj, int(sqlQuery['connection_parameter_port']), {"name":"connection_parameter_port"})
                    except:
                        pass
                    addAttributes(ipAddr, detailObj, sqlQuery['integration_point_name'], {"name":"integration_point_name"})
                    for definition in patternDefines:
                        if definition['query_value'][0] == label:
                            addAttributes(ipAddr, detailObj, definition['name'], {"name":"query_name"})

                    if qryAttributes and len(qryAttributes) > 0:
                        addAttributes(ipAddr, detailObj, str(qryAttributes), {"name":"returned_attributes","type":"list"})
                        #print("Attributes: %s" % len(qryAttributes))
                        for resultRow in sqlResultRows:
                            if resultRow['endpoint'] == endpointHash and resultRow['provider_hash'] == queryHash:
                                print("Endpoints: %s <> %s ... Providers: %s <> %s" % (resultRow['endpoint'], endpointHash, resultRow['provider_hash'], queryHash))
                                integrationrow = objectify.Element("integrationrow")
                                integrationresult.append(integrationrow)
                                for i, v in resultRow.items():
                                    #print("key: %s, value: %s" %(i,v))
                                    if i not in [ "endpoint", "provider_hash" ]:
                                        if v:
                                            try:
                                                addAttributes(ipAddr, integrationrow, int(v), {"name":i,"type":"int"})
                                            except:
                                                if v == "false" or v == "true":
                                                    #print(">>>key, value : %s, %s" % (i,v) )
                                                    addAttributes(ipAddr, integrationrow, str(v).capitalize(), {"name":i,"type":"bool"})
                                                else:
                                                    addAttributes(ipAddr, integrationrow, v, {"name":i})

# remove lxml annotation
objectify.deannotate(root)
etree.cleanup_namespaces(root)

# create the xml string
xmlparser = etree.XMLParser(remove_blank_text=True)
xml = etree.tostring(root)
#print(xml)
file_obj = BytesIO(xml)
tree = etree.parse(file_obj, xmlparser)

try:
    with open("hosts.dml", "wb") as xml_writer:
        xml_writer.write('<?xml version="1.1" encoding="UTF-8"?>\n'.encode('utf8'))
        tree.write(xml_writer, pretty_print=True, encoding='UTF-8')
except IOError:
    msg = "There was an issue writing to the XML file!"
    print(msg)
    logger.error(msg)
    sys.exit(1)

logger.info("---End---")
f.close()
