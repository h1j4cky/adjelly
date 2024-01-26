#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   DCE/RPC lookup sid brute forcer example
#
# Author:
#   Alberto Solino (@agsolino) - lookupsid.py
#   @hijacky - modified version
#
# Reference for:
#   DCE/RPC [MS-LSAT]
#

from __future__ import division
from __future__ import print_function
from termcolor import colored
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED


class LSALookupSid:
    KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port = None):
        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain

    def getSid(self, dc_ip):
        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % dc_ip
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(dc_ip)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain)
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp['PolicyHandle']
            resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
            domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        except Exception as e:
            print(colored(f"[-] Error occured: {e}",'red'))
            exit(1)
        return domainSid
        

def main(dc_ip, domain, username, password):
    lookup = LSALookupSid(username, password, domain, int('445'))
    return lookup.getSid(dc_ip)
