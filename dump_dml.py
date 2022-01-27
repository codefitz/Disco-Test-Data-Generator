#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Dump a DML export using get_dml script.
#
# Author: Wes Moskal-Fitzpatrick (Traversys Limited)
#
# Change History
# --------------
# 2021-03-11 : WMF : Created.
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
import zlib
import binascii

pwd = os.getcwd()

logfile = '%s/dump_dml_%s.log' % ( pwd,str(datetime.date.today() ))
logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger(__name__)

logger.info("Dumping...")

### Capture Arguments
argv = sys.argv[1:] # Additional Args

parser = argparse.ArgumentParser(description='Dump DML data.')
parser.add_argument('-f', '--file', dest='file', type=str,
                    required=False, metavar="FILENAME",
                    help='Input file containing GPG, DML or Hash.\n')
parser.add_argument('-d', '--decrypt', dest='dfile', default=False,
                    action='store_true', help='File is encrypted DML file.\n')
parser.add_argument('-b', '--bhash', dest='bfile', default=False,
                    action='store_true', help='File contains base64 hash.\n')
parser.add_argument('-c', '--compressed', dest='cfile', default=False,
                    action='store_true', help='File contains compressed data string.\n')

args = parser.parse_args()
if not (args.file or args.bfile):
    msg = "Must supply an input file!\nUse -h or --help for more information."
    print(msg)
    logger.error(msg)
    sys.exit(1)

file = args.file
filed = args.dfile
fileh = args.bfile
filec = args.cfile

if not file:
    msg = "Nothing to dump."
    print(msg)
    logger.error(msg)
    sys.exit(1)

passwd = getpass.getpass(prompt='Passphrase: ')
if not passwd:
    msg = "No passphrase supplied."
    print(msg)
    logger.error(msg)
    sys.exit(1)

# Sanitization
passwd = passwd.replace("(","\(").replace(")","\)").replace("$","\$")

if fileh:
    msg = "Converting from Hash..."
    print(msg)
    with open(file, "r") as bhash:
        if filed:
            ext="data.gpg"
        else:
            ext="data.dml"
        path=os.path.join(pwd, ext)
        decoded=base64.b64decode(bhash.read())
        outf = open(path, 'wb')
        outf.write(decoded)
        outf.close()
elif filec:
    msg = "Decompressing..."
    print(msg)
    with open(file, "r") as compacted:
        if filed:
            ext="data.gpg"
        else:
            ext="data.dml"
        path=os.path.join(pwd, ext)
        decompressed = zlib.decompress(binascii.unhexlify(compacted.read()))
        outf = open(path, 'wb')
        outf.write(decompressed)
        outf.close()

if filed:
   try:
        exitcode = os.system('echo "%s" | gpg -d --batch --yes --quiet --ignore-mdc-error --passphrase-fd 0 -o %s --decrypt %s' % (passwd, pwd+"/data.dml", file))
        if exitcode == 0:
            msg = "DML successfully decrypted!"
            print(msg)
            logger.info(msg)
            os.remove(file)
        else:
            msg = "Problem with decrypting file: Exit Code %d" % exitcode
            print(msg)
            logger.critical(msg)
            sys.exit(1)
   except Exception as e:
        msg = "Problem with file!\n"
        print(msg + str(e))
        logger.error(msg + str(e))
