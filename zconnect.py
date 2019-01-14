'''
Created `06/12/2014 09:38`

@author jbarnett@tableausoftware.com

zconnect.py: zabbix API stuff
'''
from pyzabbix import ZabbixAPI
from getpass import getpass

username = raw_input("Enter username: ")
password = getpass()

zapi_sea = ZabbixAPI("http://1seadvvlzabbix01/zabbix")
zapi_sea.login(username, password)

zapi_krk = ZabbixAPI("http://devitzabbix/")
zapi_krk.login(username, password)

zapi_new = ZabbixAPI("https://zabbix.dev.tsi.lan/")
zapi_new.login(username, password)

## get hostgroup groupids and names
#for group in zapi.hostgroup.get(output=['name']):
#    print(group['groupid'], group['name'])

## add hostgroups and groupids from new server to dict, because zapi.hostgroup.exists() is broken and returns True for everything and cannot be used
zapi_new.hostgroup.exists(name='BizSystems ALPO', nodeids=['0'])  ## works!!!
hostgroups = {group['name']:group['groupid'] for group in zapi_new.hostgroup.get(output=['name'])}

## create groups from old SEA zabbix on new zabbix if they don't exist. Will possibly need to regenerate hostgroups dict after this to retrieve new values just added
for group in zapi_sea.hostgroup.get(output=['name']):
   if group['name'] not in hostgroups.keys():
      zapi_new.hostgroup.create({'name': group['name']})

## create groups from old KRK zabbix on new zabbix if they don't exist.
for group in zapi_krk.hostgroup.get(output=['name']):
   if group['name'] not in hostgroups.keys():
      zapi_new.hostgroup.create({'name': group['name']})

## get templateid and names
#zapi_new.template.get(output=['name'])

##put templates into dict
templates = {template['name']:template['templateid'] for template in zapi_new.template.get(output=['name'])}

##create templates on new zabbix from SEA zabbix that don't already exist. Will possibly need to regenerate templates dict after this to retrieve new values just added
for template in zapi_sea.template.get(output=['name']):
    if template['name'] not in templates.keys():
        zapi_new.template.create({'host': template['name'], 'groups': {'groupid': 1}})

##create templates on new zabbix from KRK zabbix that don't already exist.
for template in zapi_krk.template.get(output=['name']):
    if template['name'] not in templates.keys():
        zapi_new.template.create({'host': template['name'], 'groups': {'groupid': 1}})


##put actions into dict
actions = {action['name']:action['actionid'] for action in zapi_new.action.get(output=['name'])}

##create actions on new zabbix from SEA zabbix if they don't already exist. Will possibly need to regenerate actions dict after this to retrieve new values just added
for action in zapi_sea.action.get(output=['name']):
    if action['name'] not in actions.keys():
        zapi_new.action.create({'host': template['name'], 'groups': {'groupid': 1}})

# for action in zapi_sea.action.get(output=['name', 'status', 'def_longdata', 'def_shortdata', 'recovery_msg', 'r_shortdata', 'r_longdata']):
#     if action['name'] not in actions.keys():
#         zapi_new.action.create({'name': action['name'], 'status': action['status'], 'def_shortdata': action['def_shortdata'], 'def_longdata': action['def_longdata'], 'operations': [})

## usergroups dict from new zabbix
usergroups = {group['name']:group['usrgrpid'] for group in zapi_new.usergroup.get(output=['name'])}

#create usergroup from SEA to new zabbix if not exist
for group in zapi_sea.usergroup.get(output=['name']):
   if group['name'] not in usergroups.keys():
      zapi_new.usergroup.create({'name': group['name']})

#create usergroup from KRK to new zabbix if not exist
for group in zapi_krk.usergroup.get(output=['name']):
   if group['name'] not in usergroups.keys():
      zapi_new.usergroup.create({'name': group['name']})



## users dict from new zabbix
users = {user['alias']:user['userid'] for user in zapi_new.user.get(output=['name', 'alias'])}


#create users from SEA to new zabbix if not exist
for user in zapi_sea.user.get(output=['name']):
   if user['name'] not in users.keys():
      zapi_new.user.create({'name': user['name']})

#create users from KRK to new zabbix if not exist
for user in zapi_krk.user.get(output=['name']):
   if user['name'] not in users.keys():
      zapi_new.user.create({'name': user['name']})


#zapi_new.user.create({'alias': 'towens', 'name': 'Tim', 'surname': 'Owens', 'lang': 'en_US', 'passwd': '1234', 'type': '3', 'usrgrps': [{'usrgrpid': '7'}, {'usrgrpid': '17'}, {'usrgrpid': '15'}], 'user_medias': [{'mediatypeid': '1', 'sendto': 'towens@tableausoftware.com', 'active': 0, 'severity': 63, 'period': '1-7,00:00-24:00'}]})

#get users from SEA and create on new Zabbix
for user in zapi_sea.user.get(output=['name', 'surname', 'alias', 'type']):
    if user['name'] != 'Default' and user['name'] != '' and user['name'] != 'guest' and user['name'] != 'Zabbix' and user['alias'] not in users.keys():
        zapi_new.user.create({'alias': user['alias'], 'name': user['name'], 'surname': user['surname'], 'lang': 'en_US', 'passwd': '1234', 'type': user['type'], 'usrgrps': [{'usrgrpid': '16'}], 'user_medias': [{'mediatypeid': '1', 'sendto': user['alias'] + '@tableausoftware.com', 'active': 0, 'severity': 63, 'period': '1-7,00:00-24:00'}]})


#get users from KRK and create on new Zabbix
for user in zapi_krk.user.get(output=['name', 'surname', 'alias', 'type']):
    if user['name'] != 'Default' and user['name'] != '' and user['name'] != 'guest' and user['name'] != 'Zabbix' and user['alias'] not in users.keys():
        zapi_new.user.create({'alias': user['alias'], 'name': user['name'], 'surname': user['surname'], 'lang': 'en_US', 'passwd': '1234', 'type': user['type'], 'usrgrps': [{'usrgrpid': '16'}], 'user_medias': [{'mediatypeid': '1', 'sendto': user['alias'] + '@tableausoftware.com', 'active': 0, 'severity': 63, 'period': '1-7,00:00-24:00'}]})


#add users to specified groups from csv file:
with open("users.csv", "rb") as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        zapi_new.user.update({'userid': row[1], 'usrgrps': row[2:]})


## get actions, conditions, operations:
#operations[op]['opmessage_grp'][0]['usrgrpid']
def_actions = ['Auto discovery. Linux servers.', 'Report not supported items', 'Report not supported low level discovery rules', 'Report unknown triggers', 'Default registration action', 'Zabbix servers alert']
for action in zapi_sea.action.get(output='extend', selectOperations='extend', selectConditions='extend'):
    if action['name'] not in def_actions:
    #condids = [cond for cond in action['conditions']]
    #if action['name'] =='Build servers - Linux alert':
        operations = action['operations']
        for op in operations:
            zapi_new.action.create({
            "name": action['name'],
            "eventsource": action['eventsource'],
            "evaltype": action['evaltype'],
            "status": action['status'],
            "esc_period": action['esc_period'],
            "def_shortdata": action['def_shortdata'],
            "def_longdata": action['def_longdata'].replace("devitzabbix", "zabbix.dev"),
            "esc_period": action['esc_period'],
            "recovery_msg": action['recovery_msg'],
            "r_shortdata": action['r_shortdata'],
            "r_longdata": action['r_longdata'].replace("devitzabbix", "zabbix.dev"),
            "conditions": [
               {
                "conditiontype": 16,
                "operator": 7,
                "value": ""
                },
                {
                "conditiontype": 5,
                "operator": 0,
                "value": "1"
                },
                {
                "conditiontype": 4,
                "operator": 5,
                "value": "2"
                }
            ],
            "operations": [
               {
                "operationtype": operations[op]['operationtype'],
                "esc_period": operations[op]['esc_period'],
                "esc_step_from": operations[op]['esc_step_from'],
                "esc_step_to": operations[op]['esc_step_to'],
                "evaltype": operations[op]['evaltype'],
                "opmessage_grp": [
                    {
                        "usrgrpid": "32"
                    }
                 ],
                "opmessage": {
                    "default_msg": operations[op]['opmessage']['default_msg'],
                    "mediatypeid": "1"
                }
               }]})


## get hosts in hostgroup with groupid 23
zapi_new.host.get(output='shorten', groupids='23')

## get specific host info
zapi.host.get(output='extend', filter={'host': 'dvcrashpw001'})

##get hostid from hostname
zapi.host.get(output='extend', filter={'host': 'dvcrashpw001'})[0]['hostid']

##get hostname from hostid
zapi.host.get(output='extend', hostids='10158')[0]['name']

##add snmp interface to zabbix host
zapi.hostinterface.massadd(hosts=[{'hostid': '10798'}], interfaces = {'type': 2, 'dns': 'dvcrashpw001-drac.tsi.lan', 'ip': '10.26.132.101', 'main': 1, 'port': '161', 'useip': 1})

##check if host snmp interface exists
zapi.hostinterface.exists(hostid='10236', dns='1krkdvpwbld138-drac.tsi.lan')

##add snmp interfaces to hostgroup id = 28 (or whatever)
#loop through hostids and place into list
import socket
def getHostname(hostid):
    return zapi.host.get(output='extend', hostids=hostid)[0]['name']

def getDRACIP(hostname):
    return socket.gethostbyname(hostname)
hostids = []
[hostids.append(host['hostid']) for host in zapi.host.get(output='shorten', groupids='28')]
for id in hostids:
    hostname = getHostname(id)
    zapi.hostinterface.massadd(hosts=[{'hostid': id}], interfaces = {'type': 2, 'dns': "{0}-{1}".format(hostname), "drac.tsi.lan"), 'ip': getDRACIP(hostname), 'main': 1, 'port': '161', 'useip': 1})



