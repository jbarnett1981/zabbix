#!/usr/bin/python

'''
Created `06/25/2014 11:50`

@author jbarnett@tableausoftware.com

zinterface_add.py: create SNMP interfaces on hardware hosts based on host group ID, using the host's DRAC name and IP
'''
import socket
from pyzabbix import ZabbixAPI, ZabbixAPIException
from getpass import getpass

username = raw_input("Enter username: ")
password = getpass()

zapi = ZabbixAPI("https://zabbix.dev.tsi.lan/")
zapi.login(username, password)

def getHostname(hostid):
    return zapi.host.get(output='extend', hostids=hostid)[0]['host']

def getDRACIP(dracdns):
    try:
        return socket.gethostbyname(dracdns)
    except socket.gaierror:
        return 0

hostids = [host['hostid'] for host in zapi.host.get(output='shorten', groupids='110')]

for id in hostids:
    try:
        hostname = getHostname(id)
        dracname = hostname + "-drac.dev.tsi.lan"
        dracip = getDRACIP(dracname)
        if dracip == 0:
            print("%s does not seem to have a DRAC interface in DNS" % hostname)
        #if "1krkdvpwbld15" in hostname and dracip != 0:
        else:
            zapi.hostinterface.create(hostid=id, dns=dracname, ip=getDRACIP(dracname), main=1, port='161', type=2, useip=0)
            print("Added SNMP Interface IP: %s DNS: %s to %s\n" % (getDRACIP(dracname), dracname, hostname))
    except ZabbixAPIException as e:
         print("{0}: {1}".format(hostname, str(e)[33:99]))
         continue

