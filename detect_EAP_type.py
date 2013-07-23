from scapy.all import *
conf.iface="mon0"
output="Invalid"
while (output=="Invalid"):
	packets=sniff(iface="mon0",count=50, filter="wlan proto 0x888e",timeout=5)
	#packets=rdpcap("/home/raiton/Bureau/captured_pcpap/cap1")
	for pkt in packets:
		try:
			if pkt[5].code==2:
				if pkt[5].type!=3:
					print pkt[5].type
		 			type_number= pkt[5].type
			output="Invalid"
			if type_number==25:
				output="PEAP"
			elif type_number==13:
				output="EAP-TLS"
			elif type_number==21:
				output="EAP-TTLS"
			elif type_number==43:
				output="EAP-FAST"
			elif type_number==17:
				output="LEAP"
			print output
		except Exception, e:
			pass