#!/usr/bin/env python

'''
Created `06/14/2016 04:27`

@author jbarnett@tableau.com

zconn.py: update agent interface to use DNS, clear IP and update DNS Name to use specified domain
add to hostgroups, add specific templates, status object status
'''
import csv, sys, os
from zabbix_api import ZabbixAPI, ZabbixAPIException, Already_Exists
from getpass import getpass
import argparse
import requests
import re
import inspect

# Globally disable deprecated urllib3 warnings in requests package (used by pyzabbix)
requests.packages.urllib3.disable_warnings()

class zConn:
    def __init__(self, username, password, api):
        '''
        Connection class for Zabbix API with custom functions
        '''
        if os.environ.has_key("REQUESTS_CA_BUNDLE"):
            cert_path = os.environ['REQUESTS_CA_BUNDLE']
        else:
            sys.exit("REQUESTS_CA_BUNDLE environment not set. Please ensure this env var is available and points to the path of the dvcertauth.pem cert file")
        self.username = username
        self.password = password
        session=requests.Session()
        session.timeout = 3
        session.get(api, verify=cert_path)
        self.zapi = ZabbixAPI(api, session=session)
        try:
            self.zapi.login(username, password)
        except ZabbixAPIException:
            sys.exit("Login failed. Please check credentials and try again.")

    def get_hostgroups(self):
        ''' Return a dictionary of hostgroups with key=name and value=groupid '''
        groups_dict = {}
        groups = self.zapi.hostgroup.getobjects({"output": ["name"]})
        for hg in groups:
            groups_dict[hg['name']] = hg['groupid']

        return groups_dict

    def get_templates(self):
        ''' List all templates and their IDs '''
        templates_dict = {}
        templates = self.zapi.template.get({"output": ["name"]})
        for t in templates:
            templates_dict[t['name']] = t['templateid']

        return templates_dict

    def get_templateid(self, templatename):
        ''' Return template ID from template name'''
        return self.zapi.template.get({"output": "extend", "filter": {"host": [templatename]}})[0]['templateid']

    def get_hostname(self,hostid):
        ''' Return hostname from hostid '''
        return self.zapi.host.get({"output":"extend", "hostids": hostid})[0]['host']

    def get_hostid(self, hostname):
        ''' Return hostid from hostname '''
        return self.zapi.host.get({"output":"extend", "filter": {"host": hostname}})[0]['hostid']

    def get_groupname(self,groupid):
        ''' Return groupname from groupid. unused for now '''
        return self.zapi.hostgroup.get({"output":"extend", "groupids": groupid})[0]['name']

    def get_groupid(self,groupname):
        ''' Return groupid from groupname '''
        return self.zapi.hostgroup.get({"output": "extend", "filter": {"name": groupname}})[0]['groupid']

    def get_hosts_in_group(self,hostgroup):
        ''' Return dictionary of all hosts and hostids in hostgroup '''
        if not is_number(hostgroup):
            hostgroup = self.get_groupid(hostgroup)

        host_dict = {}
        hostids = [host['hostid'] for host in self.zapi.host.get({"output":"shorten", "groupids": hostgroup})]

        for hostid in hostids:
            host_dict[self.get_hostname(hostid)] = hostid

        return host_dict

    def add_interface(self, int_type, host, dns, port, use_ip, ip):
        ''' Add interface to host with ip and dns '''
        if int_type == "agent":
            int_type = 1
            if port == None:
                port = "10050"
        if int_type == "snmp":
            int_type = 2
            if port == None:
                port = "161"
            dns = host + "-drac.dev.tsi.lan"
        if int_type == "ipmi":
            int_type = 3
        if int_type == "jmx":
            int_type = 4

        hostid = self.get_hostid(host)

        try:
            self.zapi.hostinterface.create({"hostid":hostid, "dns":dns, "ip":ip, "main": 1, "port": port, "type": int_type, "useip": use_ip})
            return
        except Exception as e:
            return e

    def update_interface(self, int_type, hostname, dnsname, use_ip, ip):
        '''  Update a specific interface '''
        hostid = self.get_hostid(hostname)

        if int_type == "agent":
            index = 0
        if int_type == "snmp":
            dnsname = hostname + "-drac.dev.tsi.lan"
            index = 1
        try:
            interfaceid = self.zapi.hostinterface.get(output='extend', hostids=hostid)[index]['interfaceid']
            self.zapi.hostinterface.update({"output":"extend", "interfaceid":interfaceid, "ip":ip, "dns":dnsname, "useip":use_ip})
            return
        except Exception as e:
            sys.exit("ERROR: Interface does not exist.")

    def delete_interface(self, int_type, hostname):
        ''' Delete host interface '''
        hostid = self.get_hostid(hostname)
        if int_type == "agent":
            index = 0
        if int_type == "snmp":
            index = 1
        interfaceid = self.zapi.hostinterface.get({"output":"extend", "hostids":hostid})[index]['interfaceid']
        self.zapi.hostinterface.delete(interfaceid)

    def add_to_hostgroup(self, hostgroup, hostname):
        ''' Add host to specified hostgroup '''
        hostid = self.get_hostid(hostname)
        grouplist = self.list_names_to_ids(hostgroup)
        self.zapi.host.update({"hostid":hostid, "groups": grouplist})

    def link_template(self, template, hostname):
        ''' Link templates to host '''
        templatelist = self.list_names_to_ids(template)
        hostid = self.get_hostid(hostname)
        self.zapi.host.update({"hostid": hostid, "templates": templatelist})

    def unlink_template(self, templateid, hostname):
        ''' Unlink template(s) from host '''
        # NOT IMPLEMENTED YET
        pass


    def list_names_to_ids(self, clist):
        ''' Determine if items in a list are numbers or strings containing numbers and if not queries the system for the templateid to return the associated number id '''
        #print('grouplist' in inspect.stack()[1][4][0])
        caller_name = inspect.stack()[1][4][0]
        if 'template' in caller_name:
            command = self.get_templateid
        if 'group' in caller_name in caller_name:
            command = self.get_groupid
        newlist = []
        for i in clist:
            if not is_number(i):
                i = str(command(i))
            newlist.append(i)
        return newlist

    def create_host(self, dnsname, hostgroup, templates, status, snmp_create):
        ''' Creates host with associated IP and interfaces without agent installed '''
        hostname = dnsname.partition('.')[0]
        groupid = int(self.list_names_to_ids(hostgroup)[0])
        #print(grouplist)
        templatelist = self.list_names_to_ids(templates)
        #print(templatelist)
        if status == False:
            status = "1"
        else:
            status = "0"
        if snmp_create == False:
            self.zapi.host.create({"host": hostname, "interfaces":[{"type": 1, "main": 1, "useip": 0, "ip": "", "dns": dnsname, "port": 10050}], "groups":[{"groupid": groupid}], "templates": templatelist, "status": "1" })
        else:
            oobdns = hostname + "-drac.dev.tsi.lan"
            self.zapi.host.create({"host": hostname, "interfaces":[{"type": 1, "main": 1, "useip": 0, "ip": "", "dns": dnsname, "port": 10050}, {"type": 2, "main": 1, "useip": 0, "ip": "", "dns": oobdns, "port": 161}], "groups":[{"groupid": groupid}], "templates": templatelist, "status": "1" })


def host_regex(hostname):
    regex = '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.)(.*)$'
    m = re.search(regex, hostname)
    try:
        output = m.group(0)
    except AttributeError:
        msg = '%s is not in FQDN format' % hostname
        raise argparse.ArgumentTypeError(msg)
    return output

def is_number(num):
    ''' Test if value can be converted to a number and if so return True '''
    try:
        int(num)
        return True
    except ValueError:
        return False

def get_args():
    '''
    Supports the command-line arguments listed below.
    '''
    parser = argparse.ArgumentParser(description='Zabbix API implementation')

    credentials_parser = parser.add_argument_group('required login arguments')
    credentials_parser.add_argument('--username', required=True, help='username to authenticate to Zabbix')
    credentials_parser.add_argument('--password', required=True, help='password to authenticate to Zabbix')
    credentials_parser.add_argument('--apiurl', required=True, help='API URL to authenticate to Zabbix')

    subparsers = parser.add_subparsers(help='commands')

    # list subparser
    list_parser = subparsers.add_parser('list', help='List command. Prints to stdout', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="syntax:\npython zconn.py --username <username> --password <password> --apiurl https://zabbix.dev.tsi.lan list --groups\npython zconn.py --username <username> --password <password> --apiurl https://zabbix.dev.tsi.lan list --group 8\npython zconn.py --username <username> --password <password> --apiurl https://zabbix.dev.tsi.lan list --group 'Databases - DevIT'")
    list_parser.set_defaults(which='list')
    list_group = list_parser.add_mutually_exclusive_group(required=True)
    list_group.add_argument('--templates', action="store_true", help='list templates')
    list_group.add_argument('--groups', action="store_true", help='list all hostgroups')
    list_group.add_argument('--group', help='list hosts in specific hostgroup')

    # interface subparser
    int_types = ['agent', 'snmp', 'jmx', 'ipmi']
    interface_parser = subparsers.add_parser('interface', help='Interface command. Prints to stdout')
    interface_parser.set_defaults(which='interface')
    interface_group = interface_parser.add_mutually_exclusive_group()
    interface_group.set_defaults(mode="add")
    interface_group.add_argument('--add', action='store_const', dest='mode', const='add', help='add interface')
    interface_group.add_argument('--update', action='store_const', dest='mode', const='update', help='update interface')
    interface_group.add_argument('--delete', action='store_const', dest='mode', const='delete', help='delete interface')

    interface_parser.add_argument('--type', required=True, choices=int_types, help='Interface type to add. Choices are '+', '.join(int_types))
    interface_parser.add_argument('--host', required=True, type=host_regex, help='FQDN of hostname to add interface to')
    interface_parser.add_argument('--port', required=False, help='port of host interface')
    interface_parser.add_argument('--ip', required=False, help='ip of host interface')
    interface_parser.add_argument('--use_ip', action='store_true', required=False, default=False, help='if enabled will use ip instead of dns to connect to interface')

    template_parser = subparsers.add_parser('template', help='Template command. Prints to stdout')
    template_parser.set_defaults(which='template')
    template_group = template_parser.add_mutually_exclusive_group()
    template_group.set_defaults(mode="link")
    template_group.add_argument('--link', action='store_const', dest='mode', const='link', help='link template to host')
    template_group.add_argument('--unlink', action='store_const', dest='mode', const='unlink', help='unlink template from host')
    template_parser.add_argument('--name', required=True, nargs='+', help='name or id of template to link/unlink')
    template_parser.add_argument('--host', required=True, type=host_regex, help='FQDN of hostname to link/unlink template from')

    # group subparser
    group_parser = subparsers.add_parser('group', help='Group command. Prints to stdout')
    group_parser.set_defaults(which='group')
    group_parser.add_argument('--host', required=True, type=host_regex, help='FQDN of hostname to modify group membership')
    group_parser.add_argument('--group', required=True, nargs=1, help='group name or id of valid Zabbix host group')

    add_parser = subparsers.add_parser('add', help='Interface command. Prints to stdout', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="syntax:\npython zconn.py --username <username> --password <password> --apiurl https://zabbix.dev.tsi.lan --hostname TEST-SERVER01.dev.tsi.lan --hostgroup 'Development Performance - Windows' --templates 'Template Dell Hardware,Template OS Windows'")
    add_parser.set_defaults(which='add')
    add_parser.add_argument('--hostname', required=True, type=host_regex, help='FQDN of hostname to add interface to')
    add_parser.add_argument('--hostgroup', required=True, nargs=1, help='group name or id of valid Zabbix host group')
    add_parser.add_argument('--templates', required=True, nargs='+', help='comma separated list of quoted name or ids of template to link/unlink')
    add_parser.add_argument('--enabled', required=False, action='store_true', help="boolean to enable/disable host")
    add_parser.add_argument('--no_snmp', required=False, action='store_false', help="boolean to configure snmp interface")



    args = vars(parser.parse_args())

    return args

def main():
    ''' Main function '''

    args = get_args()
    if args['username'] and args['password'] and args['apiurl'] and args['which']:
        conn = zConn(args['username'], args['password'], api=args['apiurl'])

    if args['which'] == 'list':
        print("{0:40}{1}".format("Name","ID"))
        print("-"*42)
        if args['templates']:
            templates = conn.get_templates()
            for name in sorted(templates, key=lambda s: s.lower()):
                print("{0:40}{1}".format(name,templates[name]))

        if args['groups']:
            groups = conn.get_hostgroups()
            for name in sorted(groups, key=lambda s: s.lower()):
                print("{0:40}{1}".format(name,groups[name]))

        elif args['group']:
            hosts = conn.get_hosts_in_group(args['group'])
            for name in sorted(hosts, key=lambda s: s.lower()):
                print("{0:40}{1}".format(name,hosts[name]))

    if args['which'] == 'interface':
        dnsname = args['host']
        hostname = dnsname.partition('.')[0]
        domain = dnsname.partition('.')[2]
        int_type = args['type']
        port = args['port']
        use_ip = args['use_ip']
        if use_ip == True:
            use_ip = 1
        else:
            use_ip = 0
        if args['ip']:
            ip = args['ip']
        else:
            ip = ""

        if args['mode'] == 'add':
            conn.add_interface(int_type, hostname, dnsname, port, use_ip, ip)

        elif args['mode'] == 'update':
            conn.update_interface(int_type, hostname, dnsname, use_ip, ip)

        elif args['mode'] == 'delete':
            conn.delete_interface(int_type, hostname)

    if args['which'] == 'template':
        template = args['name']
        dnsname = args['host']
        hostname = dnsname.partition('.')[0]

        if args['mode'] == 'link':
            conn.link_template(template, hostname)

        if args['mode'] == 'unlink':
            # NOT IMPLEMENTED YET
            pass

    if args['which'] == 'group':
        dnsname = args['host']
        hostname = dnsname.partition('.')[0]
        conn.add_to_hostgroup(args['group'], hostname)

    if args['which'] == 'add':
        snmp_create = args['no_snmp']
        dnsname = args['hostname']
        hostgroup = args['hostgroup']
        templates = args['templates']
        templates = templates[0].split(",")
        status = args['enabled']
        try:
            conn.create_host(dnsname, hostgroup, templates, status, snmp_create)
        except Already_Exists:
            sys.exit("Host already exists")

if __name__ == '__main__':
    main()