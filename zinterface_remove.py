#!/usr/bin/python

'''
Created `06/25/2014 11:50`

@author jbarnett@tableausoftware.com

zinterface_add.py: remove SNMP interfaces on hardware hosts based on host group ID
'''
import socket
from pyzabbix import ZabbixAPI
from getpass import getpass

username = raw_input("Enter username: ")
password = getpass()

zapi = ZabbixAPI("https://zabbix.dev.tsi.lan/")
zapi.login(username, password)

def getHostname(hostid):
    return zapi.host.get(output='extend', hostids=hostid)[0]['host']

def getDRACIP(hostname):
    return socket.gethostbyname(hostname)
hostids = []
[hostids.append(host['hostid']) for host in zapi.host.get(output='shorten', groupids='27')]
for id in hostids:
    hostname = getHostname(id)
    dracname = hostname + "-drac.tsi.lan"
    # try:
    #     interfaceid = zapi.hostinterface.get(output='extend', hostids=id)[1]['interfaceid']
    # except (IndexError):
    #     continue
    #zapi.hostinterface.delete(interfaceid)
    if "native" in hostname:
        zapi.hostinterface.massremove(hostids=[id], interfaces={'dns':dracname, 'port': '10050', 'ip': getDRACIP(dracname)})
    #print("Removed SNMP interface on %s" % hostname)
        print("Removed invalid interface on %s" % hostname)



