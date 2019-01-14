#!/usr/bin/python

'''
Created `10/24/2014 03:49`

@author jbarnett@tableausoftware.com

zquery.py: list, export, update, add to hosts/groups in zabbix via CLI
'''

import socket, argparse, platform, os, errno, json, psycopg2
from pyzabbix import ZabbixAPI, ZabbixAPIException
from getpass import getpass

# username = raw_input("Enter username: ")
# password = getpass()

def is_number(num):
    ''' Test if value can be converted to a number and if so return True '''
    try:
        int(num)
        return True
    except ValueError:
        return False

def export_to_json(data_type, choice):
    zapi = zClass(username, password)
    if choice.keys()[0] == 'group':
        group = choice['group']
        path = '/'.join([os.getcwd(), group])
        try:
            os.makedirs(path)
            hosts = zapi.getHosts(group)
            for host in hosts:
                items = zapi.getItems(host, data_type)
                conf_file = path + '/' + host + "_" + data_type + ".json"
                with open(conf_file, 'w') as outfile:
                    json.dump(items, outfile)
                print('Exported {0} for {1} to {2}'.format(data_type, host, conf_file))
        except OSError as e:
            print('{0} {1}'.format(e.strerror, path))

    else:
        host = choice['host']
        if is_number(host):
            hosts = zapi.getHostname(int(host))
        conf_file = host + "_" + data_type + ".json"
        items = zapi.getItems(host, data_type)
        with open(conf_file, 'w') as outfile:
            json.dump(items, outfile)
        print('Exported {0} for {1} to {2}'.format(data_type, host, conf_file))

class zClass:
    def __init__(self, username, password, api="https://zabbix.dev.tsi.lan/"):

        self.username = username
        self.password = password
        self.zapi = ZabbixAPI(api)
        self.login = self.zapi.login(username, password)

    def getDRACIP(dracdns):
        ''' Get DRAC IP from DNS '''
        try:
            return socket.gethostbyname(dracdns)
        except socket.gaierror:
            return 0

    def getHostgroups(self):
        ''' Return a dictionary of hostgroups with key=name and value=groupid '''
        groups_dict = {}
        groups = self.zapi.hostgroup.getobjects({"output": ["name"]})
        for hg in groups:
            groups_dict[hg['name']] = hg['groupid']

        return groups_dict

    def getHostname(self,hostid):
        ''' Return hostname from hostid '''
        return self.zapi.host.get(output='extend', hostids=hostid)[0]['host']

    def getHostID(self, hostname):
        ''' Return hostid from hostname '''
        return int(self.zapi.host.get(output='extend', filter={'host': hostname})[0]['hostid'])

    def getGroupname(self,groupid):
        ''' Return groupname from groupid. unused for now '''
        return self.zapi.hostgroup.get(output='extend', groupids=groupid)[0]['name']

    def getGroupID(self,groupname):
        ''' Return groupid from groupname '''
        return self.zapi.hostgroup.get(output='extend', filter={'name': groupname})[0]['groupid']

    def getHosts(self,hostgroup):
        ''' Return dictionary of all hosts and hostids in hostgroup '''
        if is_number(hostgroup):
            hostgroup = int(hostgroup)

        else:
            hostgroup = self.getGroupID(hostgroup)

        host_dict = {}
        hostids = [host['hostid'] for host in self.zapi.host.get(output='shorten', groupids=hostgroup)]

        for id in hostids:
            host_dict[self.getHostname(id)] = id

        return host_dict

    def getItems(self, host, data_type):
        ''' Return dictionary of items from host. key=item key, value=itemid
            Returns a list of dictionaries for triggers '''
        if is_number(host):
            host = int(host)
        else:
            host = self.getHostID(host)
        item_dict = {}
        if data_type == "items":
            items = self.zapi.item.get(output='extend', hostids=host, sortfield="name")
            for item in items:
                item_dict[item['key_']] = item['itemid']
        if data_type == "triggers":
            triggers = self.zapi.trigger.get(output='extend', hostids=host, sortfield="triggerid")
            item_dict = triggers
        return item_dict


    def zinterface_add(self, int_type, host, ip, dns, port, use_ip):
        ''' Add interface to host with ip and dns '''
        if int_type == "agent":
            int_type = 1
        if int_type == "snmp":
            int_type = 2
        if int_type == "ipmi":
            int_type = 3
        if int_type == "jmx":
            int_type = 4

        if use_ip == True:
            use_ip = 1
        else:
            use_ip = 0

        if is_number(host):
            host = int(host)
        else:
            host = self.getHostID(host)

        self.zapi.hostinterface.create(hostid=host, dns=dns, ip=ip, main=1, port=port, type=int_type, useip=use_ip)

    def zhost_update(self, host, data_type):
        conf_file = host + "_" + data_type + ".json"
        old_data = json.load(open(conf_file))
        new_data = self.getItems(host, data_type)
        for key in new_data:
            if new_data[key] != old_data[key]:
                print("{0}, new itemid:{1}, old itemid:{2}".format(key, new_data[key], old_data[key]))
                try:
                    conn = psycopg2.connect("dbname='zabbix' user='zabbix' host='zabbix.dev.tsi.lan' password='z@BB1x'")
                    cur = conn.cursor()
                    cur.execute("update history set itemid = %s where itemid = %s", (new_data[key], old_data[key]))
                    conn.commit()
                    print "Number of rows updated: %d" % cur.rowcount
                except psycopg2.DatabaseError, e:
                    if conn:
                        conn.rollback()
                    print 'Error %s' % e
                    sys.exit(1)

                finally:
                    if conn:
                        conn.close()


if __name__ == "__main__":
    # determine OS type and create config dir
    operating_system = platform.system()
    home_dir = os.path.expanduser("~")
    if operating_system == "Darwin" or OS == "Linux":
        config_dir = home_dir + "/.rstat/"

    elif operating_system == "Windows":
        config_dir = home_dir + "\\AppData\\Local\\rstat\\"

    config_file = config_dir + "creds.json"

    #collect credentials from config file
    cred_data = json.loads(open(config_file).read())
    username = cred_data['creds']['user']['username']
    password = cred_data['creds']['user']['password']

    #command line arguments
    data_choices = ('items', 'triggers', 'graphs', 'discovery_rules')
    int_types = ('agent', 'snmp', 'jmx', 'ipmi')
    parser = argparse.ArgumentParser(description='%(prog)s help')

    subparsers = parser.add_subparsers(help='commands')

    # listgroups command
    listgroup_parser = subparsers.add_parser('listgroups', help='Listgroups command. Prints to stdout')
    listgroup_parser.set_defaults(which='listgroups')
    listgroup_group = listgroup_parser.add_mutually_exclusive_group(required=True)
    listgroup_group.add_argument('-a', '--all', action="store_true", help='list all hostgroups')
    listgroup_group.add_argument('-g', '--group', help='list hosts in specific hostgroup')

    #listhost command
    listhost_parser = subparsers.add_parser('listhosts', help='Listhosts command. Prints to stdout')
    listhost_parser.set_defaults(which='listhosts')
    listhost_parser.add_argument('-t', '--type', required=True, nargs=1, choices=data_choices, help='list data types. Allowed values are '+', '.join(data_choices), metavar='')
    listhost_parser.add_argument('--host', required=True, metavar='HOSTNAME', help='hostname')


    #export command use nargs=1 for 1, nargs="+" for 1 or more, nargs="*" for 0 or more
    export_parser = subparsers.add_parser('export', help='Export data to file in JSON format')
    export_parser.set_defaults(which='export')
    export_parser.add_argument('--type', required=True, nargs=1, choices=data_choices, help='Space separated list of data types.  Allowed values are '+', '.join(data_choices), metavar='')
    groupexport = export_parser.add_mutually_exclusive_group(required=True)
    groupexport.add_argument('--host', metavar="HOSTNAME", help='hostname to export data from')
    groupexport.add_argument('--group', metavar="GROUPNAME", help='groupname to export data from')

    #update command
    update_parser = subparsers.add_parser('update', help='Update history ids from exported json data')
    update_parser.set_defaults(which='update')
    update_parser.add_argument('--type', required=True, nargs=1, choices=data_choices, help='Space separated list of data types.  Allowed values are '+', '.join(data_choices), metavar='')
    update_parser.add_argument('--host', metavar="HOSTNAME", required=True, help='hostname to update')

    #add command
    add_parser = subparsers.add_parser('add', help='Add interfaces, '+', '.join(data_choices))
    add_parser.set_defaults(which='add')
    add_parser.add_argument('-i', '--interface', required=True, nargs=1, choices=int_types, help='Interface type to add. Choices are '+', '.join(int_types), metavar='')
    add_parser.add_argument('--host', metavar="HOSTNAME", required=True, help='hostname to add interface too')
    add_parser.add_argument('--ip', metavar='', required=True, help='ip of host interface')
    add_parser.add_argument('--dns', metavar='', required=True, help='dns of host interface')
    add_parser.add_argument('--port', metavar='', required=False, help='port of host interface')
    add_parser.add_argument('--use_ip', action='store_true', required=False, help='if enabled will use ip instead of dns to connect to interface')


    parser.add_argument("--version", action="version", version="%(prog)s 0.1")

    args = vars(parser.parse_args())
    # print(args)
    # print("".join(args['type']))
    if args['which'] == 'listgroups':

        if args['all']:
            zapi = zClass(username, password)
            groups = zapi.getHostgroups()
            print("{0:40}{1}".format("Name","ID"))
            print("-"*42)
            for name in sorted(groups, key=lambda s: s.lower()):
                print("{0:40}{1}".format(name,groups[name]))

        if args['group']:
            zapi = zClass(username, password)
            hosts = zapi.getHosts(args['group'])
            for name in sorted(hosts, key=lambda s: s.lower()):
                print("{0}\t{1}".format(name,hosts[name]))


    if args['which'] == 'listhosts':
        data_type = args['type'][0]
        host = args['host']
        zapi = zClass(username, password)
        data = zapi.getItems(host, data_type)
        if data_type == "items":
            for item in sorted(data, key=lambda s: s.lower()):
                print("{0}\t{1}".format(item,data[item]))
        if data_type == "triggers":
            #print(data.__repr__())
            for item in data:
                print("{0}\t{1}".format(item['description'],item['triggerid']))

    if args['which'] == 'export':
        types = args['type']
        choice = {}
        if args['host']:
            choice['host'] = args['host']
        if args['group']:
            choice['group'] = args['group']

        export_to_json(types[0], choice)

    if args['which'] == 'update':
        data_type = args['type'][0]
        host = args['host']
        zapi = zClass(username, password)
        zapi.zhost_update(host, data_type)

    if args['which'] == 'add':
        interface = args['interface'][0]
        # print(interface)
        host = args['host']
        ip = args['ip']
        dns = args['dns']
        port = args['port']
        use_ip = args['use_ip']
        zapi = zClass(username, password)
        zapi.zinterface_add(interface, host, ip, dns, port, use_ip)
        print("Added SNMP Interface IP: %s DNS: %s to %s\n" % (ip, dns, host))


