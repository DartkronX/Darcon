#!/usr/bin/python

import time

import socket 

import urllib

import urllib2

import atexit

import pprint

import ipaddress

from bs4 import BeautifulSoup

import re

import os.path

import fcntl

import struct

import os

import threading

from threading import Thread, current_thread

import sys

import logging



import string

import resource

import subprocess

import pwd

import concurrent

import nmap

from threading import *


screen_lock = Semaphore(value=1)

os.system('clear')

nm=nmap.PortScanner()

list22 = []

list23 = []

list80 = []

list137_139 = []

list445 = []

treadsipcheck = []

well = ""

iptardict = {}

treads3000 = []

treads3000real = treads3000

limit = 10000

port_thread = ""

treadsscan = []

speedip = 9

speedport = 1999

verbose = ""

speedtime = 5

timeout = 2.5


def banner():

	print"""
				 /           /
				/' .,,,,  ./         
			       /';'     ,/    
			      / /   ,,//,`'`      
			     ( ,, '_,  ,,,' ``   
			     |    /@  ,,, ;" `  
			    /    .   ,''/' `,``   
			   /   .     ./, `,, ` ; 
			,./  .   ,-,',` ,,/''\,'   
		       |   /; ./,,'`,,'' |   |     
		       |     /   ','    /    |  
			\___/'   '     |     |  
			/ `,,'  |      /     `\  
		     Darcon  /      |        ~\  
			      '       (
			     :
			    ; .         \-- 
			  :   \         ;  

		"""

banner()

proc3=subprocess.Popen('lsof -u root |wc -l', shell=True, stdout=subprocess.PIPE, )

output=proc3.communicate()[0]

output = int(output)

resource.setrlimit(resource.RLIMIT_NOFILE, (output +limit , output + limit))


def n_map22(listall):

	listg = listall

	listall = " ".join(listall)

	print "\nScanning"

	print "\n",listg

	time.sleep(0.5)
	
	nm.scan(hosts=listall, arguments='-p 22 -O -sV --script banner --min-rate 150000') 

	b = (nm.csv())

	b = b.splitlines()

	b.pop(0)

	i = 0

	for host in nm.all_hosts():

		if host in b[i]:
			
			try:

				scripts = nm[host]['tcp'][22]['script']

			except:

				scripts = nm[host]['tcp'][22]
		
			g = (nm[host].get('osmatch','Unknown'))

			g = str(g)

			str2 = "name"

			find = g.find(str2)

			print "\n",b[i],"\n",scripts,"\n",g[find+7:]

			i = i + 1



def n_map23(listall):

	listg = listall

	listall = " ".join(listall)

	print "\nScanning"

	print "\n",listg

	time.sleep(0.5)
	
	nm.scan(hosts=listall, arguments='-p 23 -O -sV --script banner --min-rate 150000') 

	b = (nm.csv())
	
	b = b.splitlines()

	b.pop(0)


	i = 0

	for host in nm.all_hosts():

		if host in b[i]:


			try:

				scripts = nm[host]['tcp'][23]['script']

			except:

				scripts = nm[host]['tcp'][23]

			g = (nm[host].get('osmatch','Unknown'))

			g = str(g)

			str2 = "name"

			find = g.find(str2)


			print "\n",b[i],"\n",scripts,"\n",g[find+7:]

			i = i + 1


def n_map80(listall):

	listg = listall

	listall = " ".join(listall)

	print "\nScanning"

	print "\n",listg

	time.sleep(0.5)
	
	nm.scan(hosts=listall, arguments='-p80 -O --script http-server-header --min-rate 150000') 

	b = (nm.csv())

	b = b.splitlines()

	b.pop(0)

	i = 0

	for host in nm.all_hosts():

		if host in b[i]:

			
			try:

				scripts = nm[host]['tcp'][80]['script']

			except:

				scripts = nm[host]['tcp'][80]

			g = (nm[host].get('osmatch','Unknown'))

			g = str(g)

			str2 = "name"

			find = g.find(str2)


			print "\n",b[i],"\n",scripts,"\n",g[find+7:]

			i = i + 1


def n_map137_139(listall):

	listg = listall

	listall = " ".join(listall)

	wel = raw_input("1)Port 137\n2)Port 139 :")

	print "\nScanning"

	print "\n",listg

	time.sleep(0.5)

	if wel == "1":

	
		nm.scan(hosts=listall, arguments='-p137 -O -sU --script nbstat  --min-rate 150000') 

	elif wel == "2":

		nm.scan(hosts=listall, arguments='-p139 -O --script nbstat  --min-rate 150000')

	b = (nm.csv())

	b = b.splitlines()

	b.pop(0)

	i = 0

	

	for host in nm.all_hosts():

		if host in b[i]:

			if wel == "1":

				try:

					scripts = nm[host]['hostscript']

				except:

					scripts = nm[host]['tcp'][137]


			elif wel == "2":

				try:

					scripts = nm[host]['hostscript']

				except:

					scripts = nm[host]['tcp'][139]

			g = (nm[host].get('osmatch','Unknown'))

			g = str(g)

			str2 = "name"

			find = g.find(str2)


			print "\n",b[i],"\n",scripts,"\n",g[find+7:]

			i = i + 1



def n_map445(listall):

	listg = listall

	listall = " ".join(listall)

	wel = raw_input("1)Os Scan\n2)Vuln Scan :")

	print "\nScanning"

	print "\n",listg 

	time.sleep(0.5)

	if wel == "1":

	
		nm.scan(hosts=listall, arguments='-p445 -sV --script smb-os-discovery  --min-rate 150000') 

	elif wel == "2":

		nm.scan(hosts=listall, arguments='-p445 -O --script vuln  --min-rate 150000')

	b = (nm.csv())

	
	b = b.splitlines()

	b.pop(0)

	i = 0

	for host in nm.all_hosts():

		if host in b[i]:


			if wel == "1":

				try:

					scripts = nm[host]['hostscript']
	
				except:

					scripts = nm[host]['tcp'][445]


			elif wel == "2":


				try:

					scripts = nm[host]['hostscript']
			
		
				except:

					print "error "
					



			g = (nm[host].get('osmatch','Unknown'))

			g = str(g)

			str2 = "name"

			find = g.find(str2)


			print "\n",b[i],"\n",scripts,"\n",g[find+7:]

			i = i + 1






#GET = "GET / HTTP/1.1\nHost: "+ips+" \n\n"

def connCheck(ipe,port,ports_2,remainder):

	global speedtime

	global verbose

	global iptardict

	global well

	global port_thread

	global treadsscan

	#print "task start",ipe,current_thread().name

	#print "scanning port - ",port,current_thread().name ,ipe #  Add this to view the port scan progress

					
	if port == ports_2:

		d = port
		
	connSock = socket.socket()		
		
	prt = str(port)

	ips = str(ipe)

	if verbose == "1":


		print port

	try:
		

		if verbose == "2":

			print ipe,port," Trying"

		
		connSock.settimeout(speedtime)

		connSock.connect((str(ipe),port))


		screen_lock.acquire()

		print "\n\nOpen: ",ipe,"Port:",port,

		screen_lock.release()
		
		connSock.close()

		if ips in iptardict:

			iptardict[ips].append(port)

		else:

			iptardict[ips] = [port]

		if port == 22:

			if ips not in list22:

				list22.append(ips)

		elif port == 23:

			if ips not in list23:

				list23.append(ips)

		elif port == 80:

			if ips not in list80:

				list80.append(ips)

		elif (port == 137) or (port == 139):

		
			if ips not in list137_139:

				list137_139.append(ips)

		elif port == 445:

			if ips not in list445:

				list445.append(ips)

	except :
	
		if verbose == "2":

			print ipe,port, "Closed"

		connSock.close()

		pass
		
	finally:
	

		try:

			
		
			treads3000.pop(0)

			#print "Taken",ipe,len(treads3000),port


		except:	


			pass

		if port_thread < 3000:

			if port == ports_2:

				try:

					treadsscan.pop(0)

				except:

					pass
						

		elif port_thread > 3000:

			if port == (ports_2 - remainder - 1):

				try:

					treadsscan.pop(0)


				except:
				
					pass

	
	return;




def ports3000(ipe,ports_ready1,ports_ready2,remainder,ports_2):


	global treads3000

	global treads3000real

	global treadsscan
	
	for port in range(ports_ready1,ports_ready2+1):

		if len(treads3000) > speedport:

			while len(treads3000) > (speedport/4):

				time.sleep(0.03)



		threadjob = threading.Thread(target=connCheck, args=(ipe,port,ports_2,remainder,))

		threadjob.daemon = True		

		threadjob.start()

		treads3000.append(threadjob) 

		#print "Added",ipe,len(treads3000),port

	for x in treads3000:

		x.join()
		
	
def ipcheck(ipe,ports_1,ports_2,for_loops1,remainder):

	global treadsscan

	global treadsipcheck

	lols = 2

	if (ports_2 - ports_1 > 3000 ):

		for s in range(1,2):
		
			for port_s in range(1,for_loops1+1) :

				ports_ready1 = ports_1

				if port_s >= 1:

					if port_s == 1:

						ports_ready2 = 3000*port_s
		

					elif port_s > 1:
		
						ports_ready1 = 3000*(port_s - 1)	

						ports_ready2 = 3000*port_s
		
													
				elif done == "pass":

					pass	

				else: 

					pass


				if port_s == for_loops1:

					lols = "done"			
				

				threadport = threading.Thread(target=ports3000, args=(ipe,ports_ready1,ports_ready2,remainder,ports_2,))

				threadport.daemon = True
						

				threadport.start()
				
				treadsipcheck.append(threadport)
	

			if lols == "done":
		
				ports_ready1 = 3000*port_s
					
				ports_ready2 = (3000*port_s) + remainder
				
				threadport = threading.Thread(target=ports3000, args=(ipe,ports_ready1,ports_ready2,remainder,ports_2,))

				threadport.daemon = True
			
				threadport.start()

				treadsipcheck.append(threadport)

	else:

		ports_ready1 = ports_1

		ports_ready2 = ports_2			

		thread = threading.Thread(target=ports3000, args=(ipe,ports_ready1,ports_ready2,remainder,ports_2,))
			
		thread.daemon = True				

		thread.start()

		treadsipcheck.append(thread)


	for x in treadsipcheck:

		x.join()
		

def startscan():

	global verbose

	global treadsscan
	
	global port_thread

	ip_range = raw_input("\n\nType ip range\n\t--From: ")
	ip_range2 = raw_input("\n\t----To: ")
	ports_1 = int(raw_input("\n\tPorts \n\tFrom: "))
	ports_2 = int(raw_input("\n\tPorts \n\tTo: "))


	lock = threading.Lock()

	con = threading.Condition()

	start_ip = ipaddress.ip_address(u"%s" % (ip_range))

	end_ip = ipaddress.ip_address(u"%s" % (ip_range2))

	port_thread = ports_2 - ports_1

	port_hehe = ports_2 - ports_1

	port_thread = port_thread + 1

	port_threadstr = str(port_thread)

	done = ""


	ipp = int(start_ip) - int(end_ip)

	ipp = str(ipp)

	print "\n\n","From IP: ",ip_range,"\nTo IP:   ",ip_range2,"\n\n"

	for_loops1 = port_thread/3000
	remainder = port_thread%3000
	
	for ip_int in range(int(start_ip), int(end_ip + 1)):


		ipe = (ipaddress.ip_address(ip_int))


		d = ""

		if d == ipe:

			break

		if verbose == "3":

			print ipe,"ip number -:",len(treadsscan)

		if len(treadsscan) > speedip:

			while len(treadsscan) > (speedip/4):

				
				time.sleep(0.03)



		threadip = threading.Thread(target=ipcheck, args=(ipe,ports_1,ports_2,for_loops1,remainder,))

		threadip.daemon = True

		
		threadip.start()

		

		treadsscan.append(threadip)


	for x in treadsscan:

		x.join()


def makelist():

	url = "http://nirsoft.net/countryip/"

	url_connect = urllib.urlopen(url)

	if url_connect.code == 200:

		print "\t\n\t\tSuccessfuly Connected ...Downloading..."

		html1 = url_connect.read()


		list_shortlink = []

		list_full = []



		
		linklist = []


		countrylist = []

		i = 1	
		
		
	

		for line in html1.splitlines():
			if "href" in line :


				if line[(len(line) -5)] == ">" or line[22:(len(line) -4)] == "rsoft.n" or line[22:(len(line) -4)] == """ href="../main.c""""":
	
					pass

				else:
					

					linklist.append(line[13:20]) 


					i,")",line[22:len(line) - 4]

					i = i+1


					countrylist.append(line[22:len(line) - 4])
		

		d = "1"

		f = open("site.txt","w")

		for i in countrylist:

			d = str(d)

			f.write(d)

			f.write(")")

			f.write(i)

			f.write("\n")

			d = int(d) + 1

		f.close()

		f = open("site.txt","a")

		f.seek(0)

		d = "1"

		for i in linklist:

			d = str(d)

			f.write(d)

			f.write(")")	
			f.write(i)

			f.write("\n")

			d = int(d) + 1

		f.close()

		f = open("ips.txt","w")

		for i in linklist:

			url = "http://nirsoft.net/countryip/{0}".format(i)
			
			f.write(i)
			
			url_connect2 = urllib.urlopen(url)


			html2 = url_connect2.read()

			regex = []
	
		    		
			regex = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', html2)

			numb = len(regex)

			i = 0

			b = 1

			f.write("\n")

			for i in range(0,numb,2):

				f.write(regex[i])

				f.write(" - ")

				f.write(regex[b])

				f.write("\n")
								

				b = b+2

				i = i+2


		f.close()

		f = open("site.txt","r")

		print "\n\n\t All data is ready" 

		time.sleep(2)

		os.system('clear')

		banner()

		menu()

def showcountry():

	if (os.path.exists("site.txt")) and (os.path.exists("ips.txt")) :

		with open('site.txt' , 'r') as f:

			content = f.read().splitlines()

			for line in content:
				
				print line


				if "214" in line:

					break

		pick1 = raw_input("\n\nChoose a number of a country Mate: ")

		pick1_len = len(pick1)

		countryname = ""
		
		f = open('site.txt' , 'r')
	
		f.seek(0)

		pick1_ip = ""


		for i in f.readlines():

		

			if (i[0:pick1_len] == pick1) and (i[pick1_len] == ")"):

				if "html" in i:

					pick1_ip = i
				else:

					countryname = i
				
		
				
		print countryname[pick1_len +1:len(countryname)]
				

	
		f.close()
	

		with open('ips.txt') as f:
	  		content = f.readlines()
	
	
		index = [x for x in range(len(content)) if pick1_ip[pick1_len+1:pick1_len+8] in content[x].lower()]

		index = int(index[0])

		f = open('ips.txt','r') 
		mylist = f.read().splitlines()

		for i in mylist[index+1:index+10000]:


			if "html" in i:

				break
	
			else:

				print i

	else:

		print "No local files found, download first"


def sayHelloWorld():


	ped = os.getpid()

	ped = str(ped)

	os.system('kill -9 '+ped)


def menu():	

	global timeout

	global verbose

	global sayHelloWorld

	global treads3000

	global iptardict

	global treadsipcheck

	global speedtime

	global treadsscan

	global speedip

	global speedport


	global well

	atexit.register(sayHelloWorld)

	print "\nChoose function"

	k = raw_input("1) Show countries IP\n2) Scan IP range\n3) Nudes :")

	if k == "1":

		os.system('clear')

		print "Must download First"

		k1 = raw_input("1) Download\n2) Show :")

	
		if k1 == "1":

			makelist()

			time.sleep(1)

			menu()

		elif k1 == "2":

			showcountry()


			menu()

	elif k == "2":

		speed = raw_input("\n1)Start Scan\n2)Costumize :")

		if speed == "2":

			speedip = int(raw_input("\nIPs at once:"))

			speedip = speedip - 1

			speedport = int(raw_input("\nYou get errors if you choose too much,Try between 1000 and 3000 (default 2000)\nPorts at once: "))

			speedport = speedport-1

			speedtime = int(raw_input("Timeout(2-3 for internal networks 7-15 for external :"))

			verbose = raw_input("1)Verbose Ports \n2)More verbose ports\n3)Verbose IPs\n4)No verbose:")


	

			

		elif speed == "1":

			pass

		startscan()

		while len(treadsscan) != 0:

			time.sleep(timeout+5)


		print "\n\nSummery\n"

		time.sleep(1)
			
		for key in iptardict:

			iptardict[key].sort()

			print "\n",key,iptardict[key]
			
	
		k2 = raw_input("\n\nSelect port to OS scan on found hosts\n1)Port 22 SSH\n2)Port 23 Telnet\n3)Port 80 HTTP\n4)Port 137,139 NTBIOS\n5)Port 445 SMB\n6)Back : ")
		
		if k2 == "1":

			listall = list22

			n_map22(listall)
			
			time.sleep(2)

			menu()

		if k2 == "2":

			listall = list23

			n_map23(listall)
			
			time.sleep(2)

			menu()

		if k2 == "3":

			listall = list80	

			n_map80(listall)

			time.sleep(2)

			menu()

		if k2 == "4":

			listall = list137_139

			n_map137_139(listall)
			
			time.sleep(2)

			menu()

		if k2 == "5":

			listall = list445

			n_map445(listall)
			
			time.sleep(2)

			menu()
			
		elif k2 == "6":

			menu()

	elif k == "3":

		print("""
		                     . ...
		                 .''.' .    '.
		            . '' ".'.:I:.'..  '.
		          .'.:.:..,,:II:'.'.'.. '.
		        .':.'.:.:I:.:II:'.'.'.'.. '.
		      .'.'.'.'::.:.:.:I:'.'.'.'. .  '
		     ..'.'.'.:.:I::.:II:.'..'.'..    .
		    ..'.'':.:.::.:.::II::.'.'.'.'..   .
		   ..'.'.'.:.::. .:::II:..'.'.'.'.'.   .
		  .':.''.':'.'.'.:.:I:'.'.'.'.'.. '..  ..
		  ':. '.':'. ..:.::.::.:.'..'  ':.'.'.. ..
		 .:.:.':'.   '.:':I:.:.. .'.'.  ': .'.. . ..
		 '..:.:'.   .:.II:.:..   . .:.'. '.. '. .  ..
		.. :.:.'.  .:.:I:.:. .  . ..:..:. :..':. .  '.
	       .:. :.:.   .:.:I:.:. .    . ..:I::. :: ::  .. ..
	       .. :'.'.:. .:.:I:'.        ..:.:I:. :: ::.   . '.
	       '..:. .:.. .:II:'         ,,;IIIH.  ::. ':.      .
	      .:.::'.:::..:.AII;,      .::",,  :I .::. ':.       .
	      :..:'.:II:.:I:  ,,;'   ' .;:FBT"X:: ..:.. ':.    . .
	     .. :':III:. :.:A"PBF;.  . .P,IP;;":: :I:..'::. .    ..
	     . .:.:II: A.'.';,PP:" .  . ..'..' .: :.::. ':...  . ..
	     . .: .:IIIH:.   ' '.' .  ... .    .:. :.:.. :...    .'
	     . .I.::I:IIA.        ..   ...    ..::.'.'.'.: ..  . .
	      .:II.'.':IA:.      ..    ..:.  . .:.: .''.'  ..  . .
	     ..::I:,'.'::A:.  . .:'-, .-.:..  .:.::AA.. ..:.' .. .
	      ':II:I:.  ':A:. ..:'   ''.. . : ..:::AHI: ..:..'.'.
	     .':III.::.   'II:.:.,,;;;:::::". .:::AHV:: .::'' ..
	     ..":IIHI::. .  "I:..":;,,,,;;". . .:AII:: :.:'  . .
	     . . IIHHI:..'.'.'V::. ":;;;"   ...:AIIV:'.:.'  .. .
	      . . :IIHI:. .:.:.V:.   ' ' . ...:HI:' .:: :. .  ..
	      . .  ':IHII:: ::.IA..      .. .A .,,:::' .:.    .
	      :.  ...'I:I:.: .,AHHA, . .'..AHIV::' . .  :     ..
	      :. '.::::II:.I:.HIHHIHHHHHIHHIHV:'..:. .I.':. ..  '.
	   . . .. '':::I:'.::IHHHHHHHHMHMHIHI. '.'.:IHI..  '  '  '.
	    ':... .  ''" .::'.HMHI:HHHHMHHIHI. :IIHHII:. . . .    .
	     :.:.. . ..::.' .IV".:I:IIIHIHHIH. .:IHI::'.': '..  .  .
	   . .:.:: .. ::'.'.'..':.::I:I:IHHHIA.'.II.:...:' .' ... . '..
	  '..::::' ...::'.IIHII:: .:.:..:..:III:.'::' .'    .    ..  . .
	  '::.:' .''     .. :IIHI:.:.. ..: . .:I:"' ...:.:.  ..    .. ..
	     .:..::I:.  . . . .IHII:.:'   .. ..".::.:II:.:. .  ...   . ..
	  .. . .::.:.,,...-::II:.:'    . ...... . .. .:II:.::  ...  .. ..
	   ..:.::.I .    . . .. .:. .... ...:.. . . ..:.::.   :..   . ..
	    .'.::I:.      . .. ..:.... . ..... .. . ..::. .. .I:. ..' .
	  .'':.: I.       . .. ..:.. .  . .. ..... .:. .:.. .:I.'.''..
	  . .:::I:.       . . .. .:. .    .. ..  . ... .:.'.'I'  .  ...
	  . ::.:I:..     . . . ....:. . .   .... ..   .:...:.:.:. ''.''
	  '.'::'I:.       . .. ....:. .     .. . ..  ..'  .'.:..:..    '
		:. .     . .. .. .:.... .  .  .... ...   .  .:.:.:..    '.
		:.      .  . . .. .:.... . . ........       .:.:.::. .    .
		:. .     . . . . .. .::..:  . ..:.. .        ::.:.:.. .    .
		:.. .    . . .  . .. ..:.:  .. .. .:. ..     ':::.::.:. .   .
		':.. .  . . . .. .. ...::' .. ..  . .:. .     V:I:::::.. .   :.
		 ::. .  . .. .. ... .:.::  .. .  . .. .. .     VI:I:::::..   ''B
		  :.. .   . .. ..:.. ..I:... . .  . .. ... .    VII:I:I:::. .'::
		  ':.. . . . .. ..:..:.:I:.:. .  . .. . .:. .    VHIII:I::.:..':
		   ::..   . . .. ..:..:.HI:. .      . . .... .   :HHIHIII:I::..:
		   ':. .  . .. .. ..:.:.:HI:.    . . .. ..... .   HHHHIHII:I::.'
		    :.. .  . . .. .:.:.:.HI:.      . . .. ... .   IHHHHIHHIHI:'
		     :..  .  . . .. ..:..IH:.     . . .. .. ,,, . 'HHHHHHHHI:'
		     ':..   . . .. ..:.:.:HI..   .  . .. . :::::.  MIH:""'
		      :. . .  . .. ..::.:.VI:.     . . .. .:::'::. HIH
		       :..  .  . .. .:.:.:.V:.    . . . ...::I"A:. HHV
		        :. .  .  . .. ..:.:.V:.     . . ....::I::'.HV:
		         :. .  . . . .. .:..II:.  . . . ....':::' AV.'
		          :.. . . .. ... .:..VI:. . . .. .:. ..:.AV'.
		          ':.. . .  .. ..:.:.:HAI:.:...:.:.:.:.AII:.
		           I:. .  .. ... .:.:.VHHII:..:.:..:A:'.:..
		           IA..  . . .. ..:.:.:VHHHHIHIHHIHI:'.::.
		           'HA:.  . . .. ..:.:.:HHHIHIHHHIHI:..:.
		            HIA: .  . . .. ...:.VHHHIHIIHI::.:...
		            HIHI:. .  .. ... .::.HHHIIHIIHI:::..
		            HII:.:.  .  .. ... .::VHHIHI:I::.:..
		            AI:..:..  .  . .. ..:.VHIII:I::.:. .
		           AI:. ..:..  .  . .. ..' VHIII:I;... .
		          AI:. .  .:.. .  .  . ...  VHIII::... .
		        .A:. .      :.. .  . .. .:.. VHII::..  .
		       A:. . .       ::. .. .. . .:.. "VHI::.. .
		     .:.. .  .        :.. .:..... .::.. VHI:..
		    ... . .  .     . . :.:. ..:. . .::.. VI:..  .
		   .. .. .  .    . . ...:... . .. . .:::. V:..  .
		  '.. ..  .   .  .. ..:::.... .:. . ..::.. V..  .
		. . .. . .   . . .. ..:::A. ..:. . . .::.. :..
	       . .. .. .. . .  . ... ..::IA.. .. . .  ..::. :..  .
	      .. .. ... . .  .. .... .:.::IA. . .. . ..:.::. :.  .
	     . . . .. .   . . .. ..:..:.::IIA. . .  .. .:.::. :. .
	    .. . .  .   . . .. ... ..:.::I:IHA. .  . . ..:.::. . .
	   .: ..  .  .   . . ... .:.. .:I:IIHHA. .  . .. .::I:. .
	  .::.  .     . . .. ..:. .::.:IIHIIHHHA.  .  .. ..:I:. . .
	  A::..      .  .  ...:..:.::I:IHIHIHHHHA.  .  . ..::I:. .
	 :HI:.. .       . .. .:.:.::I:IHIHIIHIHHHA. .   .. .::I:. ..
	 AI:.. .. .    . .. .:.:.::II:IHIIIHIHIHHHA.  .  . ..::I:. ..
	:HI:.. . .   .  . .. .::.:I:IHIHIIIHIHIIHHHA..  . .. .::I:. ..
	AI:.:.. .  .  .  ... .::.::I:IHIIHIHIHIHIHIHHA. .  . ..::I:. .
	HI:. .. . .  .  . .. .:..::IIHIHIHIIIIWHIIHHMWA.  . . .:::I:. . .
	HI:.. . .  .   . .. ..:.::I:IIHHIIHIHIHIHHMMW"  '.. . ..:::II: . .
	HI::.. .  .   .  .. .:..:::IIHIHIIWIWIIWMWW" .    .. . ..::III: .  .
	HI::... . . .  . ... ..:.:::IIHIWIWIWMWMWW. .  .   . .. .:.:III. .   .
	II::.:.. . .  .  .. ......:..IHWHIWWMWMW".. . . . . '... .:.:IHI:..    .
	II:I::.. .  .   .  . .....::.:IHWMWWWMW:.. .  .  . .  .:..:::IIHII..
	:II:.:.:.. .  .   . ......:.:.:IWWMWWW:.:.. .  .  .  . :...:.:IHHI:..
	 HI::.:. . . .  .  . ...:.::.::.VWMWW::.:.:.. .  . .. . :.. ..:IHHI::.'-
	 HII::.:.. .  .  . .. .:..:.'.  'WWWI::.::.:.. . .  . .. ':...:II:IIII::
	 III::.:... .  .  . ...:.:... .   WII:I::.:.. .  .  .. . . :.:::...::.::
	  VII::.:.. . . . .. ...:....      VHI:I::.:.. .  . ... .. .::.:..:.:..:
	   VII::.:.. . .  . ..:.::.. .     :HHII:I::.:.. . . .. ..  .'::':......
	   III:I::.. .. . . .. .:.:.. .    :VHIHI:I::.:... . . .. .. .':. .. .AH
	  AA:II:I::.. . . .  .. ..:.. . .  ::HHIHII:I::.:... .. .. ... .:.::AHHH
	 AHH:I:I::.:.. .  . .. ..:.:.. .   ::VHHHVHI:I::.:.:.. ..:. .::.A:.AHHHM
	 HHHAII:I::.:.. . . . .. ..:.. . . :::HIHIHIHII:I::.:.. .. .:. ..AHHMMM:
	AHHHH:II:I::.:.. . . .. ..:.:.. . .:I:MMIHHHIHII:I:::.:. ..:.:.AHHHMMM:M
	HHHHHA:II:I::.. .. . . .. .:... . .:IIVMMMHIHHHIHII:I::. . .. AHHMMMM:MH
	HHHHHHA:I:I:::.. . . . ... ..:.. ..:IHIVMMHHHHIHHHIHI:I::. . AHMMMMM:HHH
	HHHHHMM:I::.:.. . . . .. ...:.:...:IIHHIMMHHHII:.:IHII::.  AHMMMMMM:HHHH
	HHHHHMMA:I:.:.:.. . . . .. ..:.:..:IIHHIMMMHHII:...:::.:.AHMMMMMMM:HHHHH
	HHHHHMMMA:I::... . . . . .. ..:.::.:IHHHIMMMHI:.:.. .::AHMMMMMMM:HHHHHHH
	VHHHHMMMMA:I::.. . .  . . .. .:.::I:IHHHIMMMMHI:.. . AHMMMMMMMM:HHHHHHHH
	 HHHMMMMMM:I:.:.. . .  . . ...:.:IIHIHHHIMMMMMHI:.AHMMMMMMMMM:HHHHHHHHHH
	 HHHHMMMMMA:I:.:.. .  .  . .. .:IIHIHHHHIMMMMMH:AMMMMMMMMMMM:HHHHHHHHHHH
	 VHHHMMMMMMA:I:::.:. . . . .. .:IHIHHHHHIMMMV"AMMMMMMMMMMMM:HHHHHHHHHHHH
	  HHHHHMMMMMA:I::.. .. .  . ...:.:IHHHHHHIM"AMMMMMMMMMMMM:HHHHHHHHHHHHHH
	  VHHHHHMMMMMA:I:.:.. . . .  .. .:IHIHHHHI:AMMMMMMMMMMMIHHHHHHHHHHHHHHHH
	   VHHHHHMMMMMA:I::.:. . .  .. .:.:IHHHV:MMMMMIMMMMMMMMMMMMMHHHHHHHHV::.
	    VHHHHMMMMMMA:::.:..:.. . .. .:::AMMMMMMMM:IIIIIHHHHHHHHHHHHHHHV:::..
	     HHHHHMMMIIIA:I::.:.:..:... AMMMMMMMMMM:IIIIIIHHHHHHHHHHHHHHHV::::::
	     VHHHHMMIIIIMA:I::::.::..AMMMMMMMMMMM:IIIIIIIHHHHHHHHHHHHHHV::::::::
	      HHHHMIIIIMMMA:II:I::AIIIMMMMMMMMMM:IIIIIIIHHHHHHHHHHHHHHV:::::::::
	      VHHHHIIIMMMMMMA:I:AIIIIIIMMMMMM:IIIIIIIIHHHHHHHHHHHHHHV::::::::"'
	       HHHHHIIMMMMMMIMAAIIIIIIIIMMM:IIIIIIIIHHHHHHHHHHHHHHHV:::::""'
	       VHHHIIIIMMMMIIIIIIIIIIIIII:IIIIIIIIHHHHHHHHHHHHHHHV::""'
		VHHIIIMMMMMIIIIIIIIIIIIIIIIIIIIIHHHHHHHHHHHHHHHV
		 VHHIMMMMMMMIIIIIIIIIIIIIIIIIHHHHHHHHHHHHHV
		  VHHHMMMMMMMMIIIIIIIIIIIHHHHHHHHHHHV
		   VHHHMMMMMMMMMMMMMHHHHHHHHHHHHHV""")

		time.sleep(3)

		menu()

menu()







