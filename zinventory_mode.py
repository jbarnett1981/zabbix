#!/usr/bin/python

'''
Created `06/26/2014 11:01`

@author jbarnett@tableausoftware.com

zinventory_mode.py: update inventory mode to automatic for hosts in group
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

hostids = []
[hostids.append(host['hostid']) for host in zapi.host.get(output='shorten', groupids='23')]

for id in hostids:
    hostname = getHostname(id)
    if "dvh" in hostname:
        zapi.host.update(hostid=id, inventory_mode='1')
        print("%s inventory mode set to: Automatic" % hostname)



