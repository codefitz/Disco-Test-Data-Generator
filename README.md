# Disco Test Data

License: GPLv3 (please share and contribute back)

Generate some random playback data for BMC Discovery

Requires
--------
* Python 3
* Pip Install: python-generate-mac
* Pip Install: faker

Quickstart
----------
1. Generate the test data file:
    `./generate_dml.py -f <config file>`
2. copy hosts.dml to Discovery Appliance
3. From the Discovery Appliance Run:
    `tw_dml_generate -u system --verbose -d <location of DML file>`
4. Run a playback scan against the test IP ranges

More Information
----------------
This is an *alpha release* script to generate partial Host data for playback on a
Demo Discovery Appliance.

The data is made up from semi-random values and imported values that can either
be generated manually, or tweaked from a Discovery API export.

It would require a lot of effort to generate fully automated/random test data,
so for quick results, you can export the following DDD from Discovery into the
JSON formatted templates provided.

Some placeholder data is provided to give you an idea of what the file should look like, but it closely resembles output from the Discovery API. In order to get embedded list results, you would need to pivot from a 'Result List' node use key expressions to the DDD. So for example, to get a list of DiscoveredProcesses you would use the following query:

	search ProcessList with (traverse DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess as DA), (traverse List:List:Member:DiscoveredProcess as DP) show #DA.endpoint as 'endpoint', #DP.cmd as 'cmd', #DP.args as 'args', #DP.username as 'username', #DP.pid as 'pid' process with unique(0)

The grouped column results are always displayed in the same order across columns, so you can then reference these in the Python JSON library using an for loop index.

The input data requires you to provide a hashed list (endpoints) to use as a
key. This will allow for raw data and software communication to be preserved.

* Discovered Command Results
* Discovered Files
* Discovered Directories
* Packages
* Patches
* Registry Queries
* WMI Queries
* Network Interfaces/Connections
* Discovered Processes
* Discovered Services
* Integration Results (SQL)
* Discovered HBAs

Some values can be null, but others are required (most are obvious). I haven't
had the time to do extensive testing so it's trial and error when you run the
`tw_dml_generate` command. As far as I can tell though, it only checks for data
validity, it doesn't do any consistency checks so you can have data that does
not match e.g. a filesystem size that is smaller than it's used size.
