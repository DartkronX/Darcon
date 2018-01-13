#!/usr/bin/python

import os

print "Checking Deps"

try:

	os.system('pip install ipaddress && pip install resource && pip install futures && pip install python-nmap')

except:

	print "error , Try installing these modules manually - ipaddress,resource,futures,python-nmap"

