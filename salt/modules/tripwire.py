'''
Module for management of tripwire.
'''

import os
import hashlib
import re

def _get_tw_path(): 
    return '/usr/sbin/tripwire'

def binaries_checksum(): 
    '''
    Returns checksums of critical tripwire files
    '''
    ret = dict()
    for binary in [ 
            _get_tw_path(),
            '/etc/tripwire/tw.cfg',
            '/etc/tripwire/tw.pol',
            ]:

        ret[binary] = dict()
        hashers = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha224': hashlib.sha224(),
                'sha256': hashlib.sha256(),
                'sha384': hashlib.sha384(),
                'sha512': hashlib.sha512(),
        }

        try:
            f = open(binary, 'r')
            while True:
                buf = f.read(512)
                if not buf:
                    break
                for key in hashers.keys(): 
                    hashers[key].update(buf)

            for key in hashers.keys():
                ret[binary][key] = hashers[key].hexdigest()
        finally:
            f.close()
    return ret

def check():
    '''
    Check tripwire status
    '''
    cmd_all = __salt__['cmd.run_all'](_get_tw_path() + ' --check')
    regex = r'^[ *]{2}(.{31})\s(.{17})\s(.{8})\s(.{8})\s(.{8}).*$'
    ret = dict()

    items = map(
            lambda g: map(
                lambda s: s.strip(), 
                g
                ),
            re.findall(
                regex,
                cmd_all['stdout'], 
                re.M
                )
            )

    for item in items: 
        try: 
            bit = {
                    'added': int(item[2]),
                    'deleted': int(item[3]),
                    'modified': int(item[4]),
                    'severity_level' : int(item[1]), 
            } 
        except ValueError:
            continue
        ret[item[0]] = bit

    return ret

