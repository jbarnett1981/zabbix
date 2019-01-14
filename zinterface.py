#!/usr/bin/python

'''
Created `11/09/2015 11:59`

@author jbarnett@tableau.com

zinterface_agent_update.py: update agent interface to use DNS, clear IP and update DNS Name to use specified domain
'''
import csv
from pyzabbix import ZabbixAPI
from getpass import getpass
import argparse
import requests

# Globally disable deprecated urllib3 warnings in requests package (used by pyzabbix)
requests.packages.urllib3.disable_warnings()

def get_host_id(conn, hostname):
    return int(conn.host.get(output='extend', filter={'host': hostname})[0]['hostid'])

def zconn():
    username = raw_input("Enter username: ")
    password = getpass("Enter Password: ")
    url = "https://zabbix.dev.tsi.lan/"
    # create requests session object to pass to ZabbixAPI with the dvcertauth.pem file
    session=requests.Session()
    session.timeout = 3
    session.get(url, verify='dvcertauth.pem')
    zapi = ZabbixAPI(url, session=session)
    zapi.login(username, password)
    return zapi

def get_args():
    '''
    Supports the command-line arguments listed below.
    '''
    parser = argparse.ArgumentParser(description='Process for adding or updating Zabbix interfaces via CLI')
    subparsers = parser.add_subparsers(help='commands')

    interface_parser = subparsers.add_parser('interface', help='interface command. Prints to stdout')
    interface_parser.set_defaults(which='interface')
    interface_parser.add_argument('-a', '--agent', action="store_true", help='configure agent interface')
    interface_parser.add_argument('-s', '--snmp', action="store_true", help='configure SNMP interface')
    interface_parser.add_argument('-c', '--csv', required=True, help='select csv file')

    args = vars(parser.parse_args())

    return args

def agent_update(conn, hostid, dnsname):
    try:
        interfaceid = conn.hostinterface.get(output='extend', hostids=hostid)[0]['interfaceid']
        conn.hostinterface.update(output='extend', interfaceid=interfaceid, ip='', dns=dnsname, useip='0')
        return 0
    except Exception as e:
        return e

def snmp_update(conn, hostid, hostname, dnsname):
    try:
        interfaceid = conn.hostinterface.get(output='extend', hostids=hostid)[1]['interfaceid']
        conn.hostinterface.update(output='extend', interfaceid=interfaceid, ip='', dns=dnsname, useip='0')
        print("SNMP interface has been updated on %s" % hostname)
    except IndexError:
        print("SNMP interface doesn't exist on %s, creating..." % hostname)
        conn.hostinterface.create(hostid=hostid, dns=dnsname, ip='', main=1, port='161', type='2', useip='0')

def main():
    ''' Main function '''

    args = get_args()

    if args['which'] == 'interface':
        # Check if interface args were passed, and setup connection and file input if so
        conn = zconn()
        hosts = csv.reader(open(args['csv']), delimiter=',')

        if args['agent'] and not args['snmp']:
            # Update agent interface config to use DNS instead of IP
            for host in hosts:
                hostname = host[0].strip()
                domain = host[1].strip()
                dnsname = hostname + "." + domain
                hostid = get_host_id(conn, hostname)
                updated = agent_update(conn, hostid, dnsname)
                if updated == 0:
                    print("Agent Interface for %s updated to use DNS Name: %s" % (hostname, dnsname))
                else:
                    print("Agent update failed: %s" % updated)

        if args['snmp'] and not args['agent']:
            # Update agent interface config to use DNS instead of IP
            for host in hosts:
                hostname = host[0].strip()
                drac_domain = "dev.tsi.lan"
                hostid = get_host_id(conn, hostname)
                dracdnsname = hostname + "-drac." + drac_domain
                snmp_update(conn, hostid, hostname, dracdnsname)

        if args['agent'] and args['snmp']:
            for host in hosts:
                hostname = host[0].strip()
                domain = host[1].strip()
                drac_domain = "dev.tsi.lan"
                dnsname = hostname + "." + domain
                dracdnsname = hostname + "-drac." + drac_domain
                hostid = get_host_id(conn, hostname)

                # Update agent interface
                updated = agent_update(conn, hostid, dnsname)
                if updated == 0:
                    print("Agent Interface for %s updated to use DNS Name: %s" % (hostname, dnsname))
                else:
                    print("Agent update failed: %s" % updated)

                # Update SNMP interface
                snmp_update(conn, hostid, hostname, dracdnsname)

if __name__ == '__main__':
    main()