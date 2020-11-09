#!/usr/bin/env python
# coding: utf-8

# In[1]:

import pandas as pd
import requests
import json 
import pysnmp
import numpy as np


# In[2]:


from pysnmp.hlapi import *
def snmp_walk(OID, device, snmp_community):
    walk_response = []
    for (errorIndication,errorStatus,errorIndex,varBinds) in nextCmd(
                              SnmpEngine(),
                              CommunityData(snmp_community, mpModel=1),
                              UdpTransportTarget((device, 161)),
                              ContextData(),
                              #ObjectType(ObjectIdentity('IF-MIB', 'ifAlias')),
                              ObjectType(ObjectIdentity(OID)),
                             lexicographicMode = False, maxCalls=0):

        # lexicographicMode = False please refer to below link:
        # snmplabs.com/pysnmp/faq/walk-whole-mib.html+&cd=1&hl=tr&ct=clnk&gl=tr

        if errorIndication:
            print(errorIndication)
            return None
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            return None
            break
        else:
            for varBind in varBinds:
                singleOid_and_values = '='.join([x.prettyPrint() for x in varBind])
                walk_response.append(singleOid_and_values)
    return np.array(walk_response)



def snmp_get(OID, device, snmp_community):
    get_response = []
    iterator = getCmd(SnmpEngine(),
                      CommunityData(snmp_community, mpModel=1),
                      UdpTransportTarget((device, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(OID)))

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:  # SNMP engine errors
        print(errorIndication)
        return None
    else:
        if errorStatus:  # SNMP agent errors
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
            return None
        else:
            for varBind in varBinds:  # SNMP response contents
                singleOid_and_values = '='.join([x.prettyPrint() for x in varBind])
                get_response.append(singleOid_and_values)
    return np.array(get_response)


# In[5]:


snmp_walk('1.3.6.1.2.1.2.2.1.10', '10.212.147.225', 'tazmania*')


# In[6]:


snmp_get('1.3.6.1.2.1.1.1.0', '10.212.147.225', 'tazmania*')
