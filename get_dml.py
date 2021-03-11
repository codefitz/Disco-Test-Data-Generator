#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generate a DML file for use in BMC Discovery for generating Playback data.
# This script has been designed to run on an appliance (v11.3-12.1) and use appliance
# built in python libraries.
#
# Author: Wes Moskal-Fitzpatrick (Traversys Limited)
#
# Change History
# --------------
# 2021-03-10 : WMF : Created.
#

import sys
import os
import subprocess
import getpass
import datetime
import logging
import argparse
import zipfile
import base64
import hashlib

# A utility function that can be used in your code
def compute_md5(file_name):
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#pwd = os.getcwd()
#dml = os.path.join(os.path.dirname(sys.argv[0]), "dml.xml")
dml = "/tmp/dml.xml"

logfile = 'get_dml_%s.log' % ( str(datetime.date.today() ))
logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger(__name__)

logger.info("get_dml script started.")

### Capture Arguments
argv = sys.argv[1:] # Additional Args

parser = argparse.ArgumentParser(description='Extract appliance data in DML format.\nThis will be automatically exported to %s' % (dml))
parser.add_argument('-u', '--username', dest='username',  type=str, required=True, help='The appliance login user.\n')
parser.add_argument('-z', '--zip', dest='zippit', default=False, action='store_true', help='Zip the DML file.')
parser.add_argument('-e', '--encrypt', dest='encrypt', default=False, action='store_true', help='Encrypt the DML file.')
parser.add_argument('-m', '--md5', dest='md5hash', default=False, action='store_true', help='Display md5 hash sum of the DML file.')
parser.add_argument('-b', '--b64', dest='encode', default=False, action='store_true', help='Output encrypted DML file to base64. Use with -e flag.')
parser.add_argument('-s', '--search', dest='query', type=str, required=True, help='The search query of nodes to export.\n')


args = parser.parse_args()
query = args.query
user = args.username
zippit = args.zippit
encrypt = args.encrypt
encode = args.encode
md5hash = args.md5hash

passwd = getpass.getpass(prompt='Please enter your appliance password: ')
if not passwd:
    msg = "ERROR: No password supplied! Please run again."
    print(msg)
    logger.error(msg)
    sys.exit(1)

cmd = 'tw_dml_extract -u %s -p %s -o %s "%s"' % (user, passwd, dml, query)

try:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = p.communicate()
    p_status = p.wait()
    output = out.decode()
    #print("%s : %s" % (err, output))
    if err:
        msg = "Problem with DML generation!\n"
        print(msg + str(e))
        logger.error(msg + str(err))
        sys.exit(1)
    elif not output:
        msg = "Query failed!\n"
        print(msg)
        logger.warning(msg)
        sys.exit(1)
    else:
        msg = "DML successfully exported to %s." % dml
        print(msg)
        logger.info(msg)
except Exception as e:
    msg = "Problem with DML generation!\n"
    print(msg + str(e))
    logger.error(msg + str(e))
    sys.exit(1)

if os.path.isfile(dml):
    #print(dml)
    if md5hash:
        hash = compute_md5(dml)
        print(hash)
        logger.info("md5 hash: " + hash)
    if zippit:
        try:
            import zlib
            compression = zipfile.ZIP_DEFLATED
        except:
            compression = zipfile.ZIP_STORED

        zf = zipfile.ZipFile('%s.zip' % dml, mode='w')
        try:
            zf.write(dml, compress_type=compression)
            print ('%s zipped successfully!' % dml)
            os.remove(dml)
        finally:
            zf.close()
    elif encrypt:
        try:
            os.system('echo %s | gpg --yes --batch --quiet --passphrase-fd 0 -o %s -c %s' % (passwd, dml+".gpg", dml))
            os.remove(dml)
            msg = "DML successfully encrytped using appliance passphrase!"
            print(msg)
            logger.info(msg)
            if encode:
                with open(dml + ".gpg", "rb") as x:
                    xb = base64.b64encode(x.read())
                    print(xb)
        except Exception as e:
            msg = "Problem with encrypting!\n"
            print(msg + str(e))
            logger.error(msg + str(e))
