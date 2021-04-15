# Disco Test Data Generation

License: GPLv3 (please share and contribute back)

Extract, Dump and anonymise Playback data for BMC Discovery.

Requires
--------
* Python 3
* Pip Install: python-generate-mac (scramble)
* Pip Install: faker (scramble)

Extract DML Data
----------------
### Usage

    get_dml.py [-h] -u USERNAME [-z] [-e] [-m] [-b] [-c] -s QUERY

    Extract appliance data in DML format. This will be automatically exported to /tmp/data.dml

    optional arguments:
	-h, --help            show this help message and exit
	-u USERNAME, --username USERNAME, The appliance login user.
	-z, --zip             Zip the DML file.
	-e, --encrypt         Encrypt the DML file.
	-m, --md5             Display md5 hash sum of the DML file.
	-b, --b64             Output encrypted DML file to base64. Use with -e flag.
	-c, --compress        Compress the DML file. Use with -e flag.
	-s QUERY, --search QUERY, The search query of nodes to export.

#### Examples

* Export DML with md5 hash of all NetworkDevice nodes

      python3 get_dml.py -u system -m --search "search NetworkDevice"

* Encrypted and compress a DML file of Windows Hosts

      python3 get_dml.py -u system -e -c --search "search Host where os_type = 'Windows'"

Dump DML Data (encrypted)
-------------------------
Encrypyed and/or compressed data.dml file will need to be decrypted and/or decompressed before import.

### Usage

    dump_dml.py [-h] [-f FILENAME] [-d] [-b] [-c]

    Dump DML data.

    optional arguments:
	-h, --help            show this help message and exit
	-f FILENAME, --file FILENAME, Input file containing GPG, DML or Hash.
	-d, --decrypt         Decrypt the DML file.
	-b, --bhash           Convert base64 hash.
	-c, --compressed      Decompressed data string.

### Examples

* Decrypt a gpg DML file

      python3 dump_dml.py -f data.gpg -d

* Convert a Base64 hashed DML string

      python3 dump_dml.py -f data.dml -b

Anonymise Data
--------------
Use this script to anonymise (scramble) hostnames, ip addresses, mac addresses and usernames. This script does not garuantee full anonymity and protection - sensitive data may be captured in process arguments and other unexpected attribute fields.

### Usage

    scramble_dml.py [-h] -f DML FILE

    Anonymise and obsfucate DML data. Replaces IP Addresses, MAC Addresses, Hostnames

    optional arguments:
	-h, --help            show this help message and exit
	-f DML FILE, --file DML FILE, The DML file for this script.

### Example

* Scramble data.dml Host data

      python3 scramble_dml.py -f data.dml

Deploy/Import
-------------
1. copy data.dml to Discovery Appliance
2. From the Discovery Appliance Run:
    `tw_dml_generate -u system --verbose -d <location of DML file>`
3. Run a playback scan against IP ranges


More Information
----------------
These scripts use undocumented commands on a Discovery Appliance to extract, encrypt and anonymise DML data for use in Playback. You should only use them if you are familiar with how Discovery Playback works with Pool and Record data.

The scripts themselves may be buggy, please submit any bugs using the Issues tab, or better yet submit a fix and pull request.
