#!/usr/bin/python

'''
Created `04/23/2015 12:19`

@author jbarnett@tableausoftware.com

zinterface_update.py: update SNMP interface to use DNS, clear IP and update DNS Name to use dev.tsi.lan
'''
import socket
from pyzabbix import ZabbixAPI
from getpass import getpass

username = raw_input("Enter username: ")
password = getpass()

zapi = ZabbixAPI("https://zabbix.dev.tsi.lan/")
zapi.login(username, password)

def getHostID(hostname):
    return int(zapi.host.get(output='extend', filter={'host': hostname})[0]['hostid'])

hosts = [line.strip() for line in open('servers.txt')]

for host in hosts:
    hostid = getHostID(host)
    dracdns = host + "-drac.dev.tsi.lan"
    dracinterface = zapi.hostinterface.get(output='extend', hostids=hostid)[1]['interfaceid']
    zapi.hostinterface.update(output='extend', interfaceid=dracinterface, ip='', dns=dracdns, useip='0')



