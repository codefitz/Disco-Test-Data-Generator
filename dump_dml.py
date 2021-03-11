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

pwd = os.getcwd()

logfile = '%s/dump_dml_%s.log' % ( pwd,str(datetime.date.today() ))
logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger(__name__)

logger.info("Dumping...")

### Capture Arguments
argv = sys.argv[1:] # Additional Args

parser = argparse.ArgumentParser(description='Dump an encrypted DML file.')
parser.add_argument('-f', '--file', dest='file', type=str,
                    required=False, metavar="FILENAME",
                    help='The GPG encrypted DML file.\n')
parser.add_argument('-b', '--bhash', dest='bfile', type=str,
                    required=False, metavar="FILENAME",
                    help='A file containing base64 hash.\n')

args = parser.parse_args()
if not (args.file or args.bfile):
    msg = "Must supply an input file!\nUse -h or --help for more information."
    print(msg)
    logger.error(msg)
    sys.exit(1)

gpg = args.file
fileh = args.bfile

passwd = getpass.getpass(prompt='Passphrase: ')
if not passwd:
    msg = "No passphrase supplied."
    print(msg)
    logger.error(msg)
    sys.exit(1)

if not gpg:
    if not fileh:
        msg = "Nothing to dump."
        print(msg)
        logger.error(msg)
        sys.exit(1)
    with open(fileh, "r") as bhash:
        gpg=os.path.join(os.path.dirname(sys.argv[0]), "dml.gpg")
        decoded=base64.b64decode(bhash.read())
        outf = open(gpg, 'wb')
        outf.write(decoded)
        outf.close()

if os.path.isfile(gpg):
   try:
        os.system('echo "%s" | gpg -d --batch --yes --quiet --no-mdc-warning --passphrase-fd 0 -o %s --decrypt %s' % (passwd, pwd+"/dml.xml", gpg))
        os.remove(gpg)
        msg = "DML successfully decrypted!"
        print(msg)
        logger.info(msg)
   except Exception as e:
        msg = "Problem with file!\n"
        print(msg + str(e))
        logger.error(msg + str(e))
