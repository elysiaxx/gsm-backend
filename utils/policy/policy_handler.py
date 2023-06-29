# -*- coding: utf-8 -*-

"""
File: policy_handler.py
Purpose: This file contains some useful and essential function utilities for handling with policy.
"""

# -*-
import os
import string
import re
import ipaddress

from sqlalchemy import modifier

from utils.policy.policy_vars import *
from utils.policy.policy_enums import *
from utils.policy.policy_util import *

# -------------------------------------------------------

# --------------------------------------------------------

def mSplit(sStr, sep_c):
    try:
        fIndex = sStr.index(sep_c)
        return [sStr[:fIndex], sStr[fIndex+1:]], None
    except:
        return [None, None], "Not found separate character"

# -------------------------- check-header ----------------------------

def check_action(action):
    '''
    Validate action in policy

    :param action: action in policy

    :return: True if action is in actions and False vice versa.
    '''
    return True if action in actions else False

def check_protocol(protocol):
    '''
    Validate protocol in policy

    :param protocol: protocol in policy

    :return: True if protocol is in protocols and False vice versa
    '''
    return True if protocol in protocols else False

def check_ip(ip_addr, type):
    '''
    Validate ip address in policy

    :param ip_addr: ip address in policy

    :return: True if ip address is in ipadds and False vice versa
    '''
    if ip_addr[0] == '!':
        if ip_addr[1:] in ipaddrs:
            return True
        return check_ip_subnet(ip_addr[1:])
        
    if ip_addr in ipaddrs:
        return True
    return check_ip_subnet(ip_addr)


def check_ip_subnet(ip):
    ip_regex = r'^((!)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2}))|any)(,(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2}))|any))*)\])$'
    return re.match(ip_regex, ip) is not None

def check_direction(direction):
    '''
    Validate direction in policy

    :param direction: direction in policy

    :return: True if direction is in directions and False vice versa
    '''
    return True if direction in directions else False

def check_port(port, type):
    '''
    Validate port in policy

    :param port: port in policy

    :return: True if port is in ports and False vice versa
    '''
    # Kiểm tra xem cổng có đúng theo quy tắc không
    if port in ports:
      return True
    port_regex = r'^((!)?\d+|(\[\d+(,\d+)*(:\d+)?\]))$'
    return re.match(port_regex, port) is not None

# ----------------------------- check-general -----------------------------

def check_priority(pri):
    '''
    Validate priority in policy

    :param priority: priority in policy

    :return: True if priority is not less than minimum and not greater than maximum and False vice versa
    '''
    return pri <= priority['maximum'] and pri >= priority['minimum']
 
def check_classtype(tp):
    '''
    Validate classtype in policy

    :param type: classtype in policy

    :return: True if type is in classtypes and False vice versa
    '''
    return True if tp in classtypes else False

def check_metadata(mtdata):
    '''
    Validate metadata in policy

    :param mtdata: metadta in policy

    :return: True if metadata is correct format and False vice versa
    '''
    for tmp in mtdata:
        [key, value], err = mSplit(tmp,' ')
        if err is not None:
            return False

        if key == "engine" and value in metadata_engine_values:
            continue
        elif key == "engine" and value not in metadata_engine_values:
            return False

        elif key == "soid":
            vals = value.split('|')
            if bool(any(is_numeric(val) for val in vals)) is False:
                return False
            continue

        elif key == "service" and value in metadata_service_values:
            continue
        elif key == "server" and value not in metadata_service_values:
            return False

        else:
            continue
    return True


def check_reference(refs):
    '''
    Validate reference in policy

    :param refs: reference in policy

    :return: True if reference is correct format and False vice versa
    '''
    for ref in refs:
        system, _ = ref.split(',')
        if system not in reference_systems:
            return False
    return True


# --------------------------------- check-detection ---------------------

def check_contents(contents):
    '''
    Validate contents in policy

    :param contents: contents list

    :return: True if contents is correct format and False vice versa
    '''
    for content in contents:
        if 'modifiers' in content.keys():
            if check_content_modifiers(content) is False:
                return False

    return True

def check_content_modifiers(modifiers):
    '''
    Validate content in policy

    :param content: content dictionary

    :return: True if content is correct format and False vice versa
    '''
    if 'rawbytes' in modifiers:
        tmp = 0
        tmp |= modifiers['http_header'] if 'http_header' in modifiers else 0
        
        tmp |= modifiers['http_raw_header'] if 'http_raw_header' in modifiers else 0
        tmp |= modifiers['http_method'] if 'http_method' in modifiers else 0
        tmp |= modifiers['http_uri'] if 'http_uri' in modifiers else 0
        
        tmp |= modifiers['http_raw_uri'] if 'http_raw_uri' in modifiers else 0
        tmp |= modifiers['http_stat_code'] if 'http_stat_code' in modifiers else 0
        tmp |= modifiers['http_stat_msg'] if 'http_stat_msg' in modifiers else 0
        
        if tmp:
            return False

    if 'fast_pattern' in modifiers:
        tmp = 0
        tmp |= modifiers['http_raw_header'] if 'http_raw_header' in modifiers else 0
        
        tmp |= modifiers['http_method'] if 'http_method' in modifiers else 0
        tmp |= modifiers['http_cookie'] if 'http_cookie' in modifiers else 0
        tmp |= modifiers['http_raw_uri'] if 'http_raw_uri' in modifiers else 0
        
        tmp |= modifiers['http_stat_code'] if 'http_stat_code' in modifiers else 0
        tmp |= modifiers['http_stat_msg'] if 'http_stat_msg' in modifiers else 0
        if tmp:
            return False

    if 'http_header' in modifiers and 'http_raw_header' in modifiers:
        if modifiers['http_header'] and modifiers['http_raw_header']:
            return False
        
    if 'http_uri' in modifiers and 'http_raw_uri' in modifiers:
        if modifiers['http_uri'] and modifiers['http_raw_uri']:
            return False
    
    # check fast_pattern
    return True
    
def check_protected_contents(pcontents):
    '''
    Validate protected_contents in policy

    :param pcontents: pcontent list

    :return: True if content is correct format and False vice versa
    '''
    for content in pcontents:
        if any( c in string.string.hexdigits for c in content['protected_content']) is False:
            return False
        if 'modifiers' in content.keys():
            if check_pcontent_modifiers(content['modifiers']) is False:
                return False

    return True

def check_pcontent_modifiers(modifiers):
    '''
    Validate protected_content in policy

    :param pcontents: pcontent dictionary

    :return: True if content is correct format and False vice versa
    '''
    if 'rawbytes' in modifiers:
        tmp = 0
        tmp |= modifiers['http_header'] if 'http_header' in modifiers else 0
        tmp |= modifiers['http_raw_header'] if 'http_raw_header' in modifiers else 0
        tmp |= modifiers['http_method'] if 'http_method' in modifiers else 0
        tmp |= modifiers['http_uri'] if 'http_uri' in modifiers else 0
        tmp |= modifiers['http_raw_uri'] if 'http_raw_uri' in modifiers else 0
        tmp |= modifiers['http_stat_code'] if 'http_stat_code' in modifiers else 0
        tmp |= modifiers['http_stat_msg'] if 'http_stat_msg' in modifiers else 0
        if tmp:
            return False
        
    if 'http_header' in modifiers and 'http_raw_header' in modifiers:
        if modifiers['http_header'] and modifiers['http_raw_header']:
            return False
        
    if 'http_uri' in modifiers and 'http_raw_uri' in modifiers:
        if modifiers['http_uri'] and modifiers['http_raw_uri']:
            return False
    
    return True

def check_http_encode(data):
    '''
    validate http_encode in policy

    :param data: http_encode string

    :return: True if http_encode is correct format and False vice versa
    '''
    pass

def check_uri_content(ucontent):
    '''
    validate uricontent in policy

    :param data: uricontent di

    :return: True if http_encode is correct format and False vice versa
    '''
    pass

def check_pkt_data(data):
    '''
    validate pkt_data in policy

    :param data: pkt_data dictionary

    :return: True if pkt_data is correct format and False vice versa
    '''
    if 'content' not in data.keys():
        return False
    if check_contents(data['content']) is False:
        return False

    return True

def check_file_data(data):
    '''
    Validate pkt_data in policy

    :param data: pkt_data dictionary

    :return: True if pkt_data is correct format and False vice versa
    '''
    if 'content' not in data.keys():
        return False
    if check_contents(data['content']) is False:
        return False
    
    return True

def check_urilen(data):
    '''
    Validate urilen in policy

    :param data: urilen string

    :return: True if urilen is correct format and False vice versa
    '''
    pass

def check_base64(data):
    '''
    Validate base64 in policy

    :param data: base64 dictionary

    :return: True if base64 is correct format and False vice versa
    '''
    if 'base64' not in data.keys():
        return False
    for bdata in data['base64']:
        keys = bdata.keys()
        if 'base64_decode' not in keys or 'content' not in keys:
            return False

        # check base_decode
        if check_content_modifiers(bdata['content']) is False:
            return False

    return True

def check_fast_pattern(fp):
    '''
    Validate fast_pattern in policy

    :param fast_pattern: fast_pattern string

    :return: True if fast_pattern is correct format and False vice versa
    '''
    pass

# --------------------------------- check-non-detection -----------------

def check_fragoffset(frag_offset):
    '''
    Validate fragoffset in policy

    :param fragoffset: fragoffset string

    :return: True if fragoffset is correct format and False vice versa
    '''
    if frag_offset[0] not in ['!', '<', '>']:
        return False
    if is_numeric(frag_offset[1:]) is False:
        return False
    return True

def check_ttl(ttl):
    '''
    Validate ttl in policy

    :param ttl: ttl string

    :return: True if ttl is correct format and False vice versa
    '''
    if ttl[0] == '=':
        if is_numeric(ttl[1:]) is False:
            return False

    if ttl[0] == '-':
        if is_numeric(ttl[1:]) is False:
            return False
            
    if ttl[0] in ['<', '>']:
        if ttl[1] == '=':
            if is_numeric(ttl[2:]) is False:
                return False
        else: 
            if is_numeric(ttl[1:]) is False:
                return False
    
    try:
        index = ttl.index('-')
        if is_numeric(ttl[:index]) is False:
            return False
        if is_numeric(ttl[index+1:]) is False:
            return False
        return True
    except:
        return False

def check_tos(tos):
    '''
    Validate tos in policy

    :param tos: tos string

    :return: True if tos is correct format and False vice versa
    '''
    return True if (tos[0] == '!' and is_numeric(tos[1:])) or is_numeric(tos) \
                else False

def check_fragbits(fragbits):
    pass

def check_dsize(dsize):
    pass

def check_flags(flags):
    '''
    Validate flags in policy

    :param flags: flags string

    :return: True if flags is correct format and False vice versa
    '''
    flags_tmp = flags.split(',')
    for bits in flags_tmp:
        for bit in bits:
            if bit not in flag_bits:
                return False
    return True
        
def check_ipopts(ipopts):
    '''
    Validate ipopts in policy

    :param ipopts: ipopts string

    :return: True if ipopts is correct format and False vice versa
    '''
    return True if ipopts in ipopts_options else False

def check_flow(flows):
    '''
    Validate flow in policy

    :param flow: flow string

    :return: True if flow is correct format and False vice versa
    '''
    flowlist = flows.split(',')
    if len(flowlist) > 4:
        return False

    for flow in flowlist:
        if flowlist.count(flow) != 1:
            return False
        if flow.strip() not in flow_options:
            return False

    return True

def check_flowbits(flowbits):
    '''
    Validate flowbits in policy

    :param flowbits: flowbits string

    :return: True if flowbits is correct format and False vice versa
    '''
    pass

def check_window(data):
    '''
    Validate window in policy

    :param data: string

    :return: True if data is correct format and False vice versa
    '''
    return True if ( data[0] == '!' and is_numeric(data[1])) \
                or is_numeric(data) \
                else False

def check_ip_proto(ip_proto):
    '''
    Validate ip_proto in policy

    :param ip_proto: ip_proto string

    :return: True if ip_proto is correct format and False vice versa
    '''
    return True if (ip_proto[0] == '!' and ip_proto[1:] in ip_protos)\
                or ip_proto in ip_protos \
                else False

def check_stream_reassemble(data):
    '''
    Validate stream_reassemble in policy

    :param data: string

    :return: True if data is correct format and False vice versa
    '''
    srlist = data.split(',')
    if len(srlist) > 4:
        return False

    if len(srlist) < 2:
        return False

    if srlist[0] not in ['enable', 'disable'] \
        or srlist[1] not in ['server', 'client', 'both']:
        return False

    if len(srlist) == 3 and srlist[2] not in ['noalert', 'fastpath']:
        return False

    if len(srlist) == 4 and (
                ['noalert', 'fastpath'].count(srlist[2]) == 0 \
                or ['noalert', 'fastpath'].count(srlist[3])
            ):
        return False
    
    return True

def check_stream_size(data):
    '''
    Validate stream_size in policy

    :param data: string

    :return: True if data is correct format and False vice versa
    '''
    sslist = data.split(',')
    if len(sslist) != 3:
        return False
    if sslist[0] not in ["server", "client", "both", "either"] \
        or sslist[1] not in [">", "<", "=", "!=", ">=", "<="] \
        or is_numeric(sslist[2].strip()):
        return False

    return True

# --------------------------------- check-post-detection -----------------

def check_logto(filename):
    '''
    Validate logto in policy

    :param filename: string

    :return: True if filename is correct format and False vice versa
    '''
    return re.match('^[a-zA-Z0-9.]+$', filename)

def check_session(session):
    '''
    Validate session in policy

    :param session: string

    :return: True if session is correct format and False vice versa
    '''
    return True if session in ["printable", "binary", "all"] else False

def check_detection_filter(data):
    '''
    Validate detection_filter in policy

    :param data: dictionary

    :return: True if data is correct format and False vice versa
    '''
    track, count, seconds = data['track'], data['count'], data['seconds']
    if track not in ['by_src', 'by_dst']:
        return False
    return True
    
# --------------------------------- 2-str ------------------------

def policy_2_str(data):
    header = header_2_str(data['header'])
    options = options_2_str(data)
    res = header + '('+ options + ')'

    return res

def header_2_str(header):
    res = ''
    res += header['action'] + ' '
    res += header['protocol'] + ' '
    res += header['source_ip'] + ' '
    res += header['source_port'] + ' '
    res += header['direction'] + ' '
    res += header['dest_ip'] + ' '
    res += header['dest_port'] + ' '
    return res

def options_2_str(data):
    keys = data.keys()
    general = data['general']
    general_keys = general.keys()

    res = ''
    res += 'msg: \"' + general['msg'] + '\";'

    if 'non_detection' in keys:
        res += non_detection_2_str(data['non_detection'])
    if 'detection' in keys:
        res += detection_2_str(data['detection'])

    if 'post_detection' in keys:
        res += post_detection_2_str(data['post_detection'])
    if 'reference' in general_keys:
        res += references_2_str(general['reference'])

    if 'priority' in data['general'].keys():
        res += 'priority: ' + str(general['priority']) + ';'
    if 'metadata' in general_keys:
        res += metadatas_2_str(general['metadata'])
    
    res += 'classtype: ' + general['classtype'] + ';'
    res += 'gid: ' + str(general['gid']) + ';'
    res += 'sid: ' + str(general['sid']) + ';'
    res += 'rev: ' + str(general['rev']) + ';'

    return res

def references_2_str(data):
    res = ''
    for ref in data:
        res += reference_2_str(ref)
    return res

def reference_2_str(ref):
    return 'reference: ' + ref + ';'

def metadatas_2_str(mtdatas):
    res = ''
    for mtdata in mtdatas:
        res += metadata_2_str(mtdata)
    return res

def metadata_2_str(mtdata):
    return 'metadata: ' + mtdata + ';'

def non_detection_2_str(data):
    keys = data.keys()
    res = ''
    if 'fragbits' in keys:
        res += 'fragbits: ' + data['fragbits'] + ';'

    if 'fragoffset' in keys:
        res += 'fragoffset: ' + data['fragoffset'] + ';'
    if 'ttl' in keys:
        res += 'ttl: ' + data['ttl'] + ';'
    
    if 'tos' in keys:
        res += 'tos: ' + data['tos'] + ';'
    if 'id' in keys:
        res += 'id: ' + str(data['id']) + ';'

    if 'ipopts' in keys:
        res += 'ipopts: ' + data['ipopts'] + ';'
    if 'dsize' in keys:
        res += 'dsize: ' + data['dsize'] + ';'
    
    if 'flags' in keys:
        res += 'flags: ' + data['flags'] + ';'
    if 'flow' in keys:
        res += 'flow: ' + data['flow'] + ';'

    if 'flowbits' in keys:
        res += 'flowbits: ' + data['flowbits'] + ';'
    if 'seq' in keys:
        res += 'seq: ' + str(data['seq']) + ';'
    
    if 'ack' in keys:
        res += 'ack: ' + data['ack'] + ';'
    if 'window' in keys:
        res += 'window: ' + data['window'] + ';'

    if 'itype' in keys:
        res += 'itype: ' + data['itype'] + ';'
    if 'icode' in keys:
        res += 'icode: ' + data['icode'] + ';'

    if 'icmp_id' in keys:
        res += 'icmp_id: ' + str(data['icmp_id']) + ';'
    if 'icmp_seq' in keys:
        res += 'icmp_seq: ' + data['icmp_seq'] + ';'

    if 'rpc' in keys:
        res += 'rpc: ' + data['rpc'] + ';'
    if 'ip_proto' in keys:
        res += 'ip_proto: ' + data['ip_proto'] + ';'
        
    if 'sameip' in keys:
        res += ' sameip;' if data['sameip'] else ''
    if 'stream_reassemble' in keys:
        res += 'stream_reassemble: ' + data['stream_reassemble'] + ';'
    if 'stream_size' in keys:
        res += 'stream_size: ' + data['stream_size'] + ';'
    
    return res

def detection_2_str(data):
    keys = data.keys()
    res = ''
    if 'content' in keys:
        res += contents_2_str(data['content'])
        
    if 'protected_contenet' in keys:
        res += pcontents_2_str(data['protected_content'])
    if 'http_encode' in keys:
        res += 'http_encode: ' + data['http_encode'] + ';'

    if 'uricontent' in keys:
        res += uricontent_2_str(data['uricontent'])
    if 'urilen' in keys:
        res += 'urilen: ' + data['urilen'] + ';'

    if 'pcre' in keys:
        res += 'pcre: "' + data['pcre'] + '";'
    if 'pkt_data' in keys:
        res += pkt_data_2_str(data['pkt_data'])

    if 'file_data' in keys:
        res += file_data_2_str(data['file_data'])
    if 'base64' in keys:
        res += base64_2_str(data['base64'])

    if 'byte_test' in keys:
        res += 'byte_test: ' + data['byte_test'] + ';'
    if 'byte_jump' in keys:
        res += 'byte_jump: ' + data['byte_jump'] + ';'

    if 'byte_extract' in keys:
        res += 'byte_jump: ' + data['byte_jump'] + ';'
    if 'byte_math' in keys:
        res += 'byte_jump: ' + data['byte_jump'] + ';'

    if 'ftpbounce' in keys:
        res += 'byte_jump: ' + data['byte_jump'] + ';'
    if 'asn1' in keys:
        res += 'byte_jump: ' + data['byte_jump'] + ';'

    if 'csv' in keys:
        res += 'byte_jump: ' + data['byte_jump'] + ';'

    return res

def post_detection_2_str(data):
    keys = data.keys()
    res = ''

    if 'logto' in keys:
        res += 'logto: ' + data['logto'] + ';'
    if 'session' in keys:
        res += 'session: ' + data['session'] + ';'

    if 'tag' in keys:
        res += 'tag: ' + data['tag'] + ';'
    if 'detection_filter' in keys:
        res += detection_filter_2_str(data['detection_filter'])

    return res

def contents_2_str(contents):
    res = ''
    for content in contents:
        res += content_2_str(content)
    return res

def content_2_str(content):
    keys = content.keys()
    res = 'content:'
    if 'negative' in keys: 
        res += '!' if content['negative'] else ''

    if 'content' in keys:
        res += '\"' + content['content'] + '\"' + ';'
    if 'modifiers' in keys:
        res += modifiers_2_str(content['modifiers'])

    return res

def pcontents_2_str(pcontents):
    res = ''
    for pcontent in pcontents:
        res += pcontent_2_str(pcontent)
    return res

def pcontent_2_str(pcontent):
    keys = pcontent.keys()
    res = 'protected_content:'
    if 'negative' in keys: 
        res += '!' if pcontent['negative'] else ''

    if 'protected_content' in keys:
        res += '\"' + pcontent['protected_content'] + '\"' + ';'

    if 'modifiers' in keys:
        res += modifiers_2_str(pcontent['modifiers'])

    return res

def uricontent_2_str(ucontent):
    keys = ucontent.keys()
    res = 'uricontent:'

    if 'negative' in keys:
        res += '!' if ucontent['negative'] else ''
    if 'uricontent' in keys:
        res += '\"' + ucontent['uricontent'] + '\"' + ';'
    
    if 'modifiers' in keys:
        res += modifiers_2_str(ucontent['modifiers'])

    return res

def pkt_datas_2_str(pkts):
    res = ''
    for pkt in pkts:
        res += pkt_data_2_str(pkt)
    return res

def pkt_data_2_str(pkt):
    res = ''
    res += 'pkt_data;'
    if 'content' in pkt.keys():
        res += content_2_str(pkt['content'])
    return res   

def file_datas_2_str(flds):
    res = ''
    for fld in flds:
        res += file_data_2_str(fld)
    return res

def file_data_2_str(fld):
    res = ''
    res += 'file_data;'
    if 'content' in fld.keys():
        res += content_2_str(fld['content'])
    return res

def base64s_2_str(base64s):
    res = ''
    for base64 in base64s['base64']:
        res += base64_2_str(base64)
    return res

def base64_2_str(base64):
    keys = base64.keys()
    res = ''

    if 'base64_decode' in keys:
        res += 'base64_decode :' + base64['base64_ddecode'] + ';'
    if 'content' in keys:
        res += content_2_str(base64['content'])
    
    return res

def modifiers_2_str(modifiers):
    keys = modifiers.keys()
    res = ''

    if 'hash' in keys:
        res += 'hash: ' + modifiers['hash'] + ';'
    if 'length' in keys:
        res += 'length: ' + str(modifiers['length']) + ';'

    if 'nocase' in keys:
        res += 'nocase;' if modifiers['nocase'] else ''
    if 'rawbytes' in keys:
        res += 'rawbytes;' if modifiers['rawbytes'] else ''
    
    if 'depth' in keys:
        res += 'depth: ' + str(modifiers['depth']) + ';'
    if 'offset' in keys:
        res += 'offset: ' + str(modifiers['offset']) + ';'
    
    if 'distance' in keys:
        res += 'distance: ' + str(modifiers['distance']) + ';'
    if 'within' in keys:
        res += 'within: ' + str(modifiers['within']) + ';'

    if 'http_client_body' in keys:
        res += 'http_client_body;' if modifiers['http_client_body'] else ''
    if 'http_cookie' in keys:
        res += 'http_cookie;' if modifiers['http_cookie'] else ''

    if 'http_raw_cookie' in keys:
        res += 'http_raw_cookie;' if modifiers['http_raw_cookie'] else ''
    if 'http_header' in keys:
        res += 'http_header;' if modifiers['http_header'] else ''

    if 'http_raw_header' in keys:
        res += 'http_raw_header;' if modifiers['http_raw_header'] else ''
    if 'http_method' in keys:
        res += 'http_method;' if modifiers['http_method'] else ''

    if 'http_uri' in keys:
        res += 'http_uri;' if modifiers['http_uri'] else ''
    if 'http_raw_uri' in keys:
        res += 'http_raw_uri;' if modifiers['http_raw_uri'] else ''

    if 'http_stat_code' in keys:
        res += 'http_stat_code;' if modifiers['http_stat_code'] else ''
    if 'http_stat_msg' in keys:
        res += 'http_stat_msg;' if modifiers['http_stat_msg'] else ''    

    if 'fast_pattern' in keys:
        res += 'fast_pattern: ' + modifiers['fast_pattern'] + ';'
    
    return res

def detection_filter_2_str(data):
    keys = data.keys()
    res = 'detection_filter: '
    res += 'track ' + data['track'] + ','
    res += 'count ' + str(data['count']) + ','
    res += 'seconds' + str(data['seconds']) + ';'
    return res


# --------------------------------- convert --------------------

def check_required_option_fields(opts_obj):
    if 'general' not in opts_obj:
        return False, 'Your policy doesn\'t have general options'
    required_options = [x for x in policy_options if x['required']]
    for opt in required_options:
        if opt['type'] == PolicyPartType.General:
            if opt['name'] not in opts_obj['general']:
                return False, "Your policy doesn't have {0} option".format(opt['name']) 
        else:
            if ["detection", "non_detection", "post_detection"][opt['type'] - 2] not in opts_obj['general']:
                return False, "Your policy doesn't have {0} option".format(opt['name'])
            if opt['name'] not in  opts_obj["detection", "non_detection", "post_detection"][opt['type'] - 2]:
                return False, "Your policy doesn't have {0} option".format(opt['name'])
    return True, None
        

def parse_policy_obj(policy):
    '''
    Parse policy line string to policy dictionary object

    :param policy: string

    :return object: policy object
    '''
    try:
        res = {}
        header, options = seperate_policy(policy)
        if header is None or options is None:
            return None, "Can't parse policy to "

        header_obj, err = parse_header(header)
        if err is not None:
            return None, err
        res['header'] = header_obj

        options_obj, err = parse_options(options)
        if err is not None:
            return None, err
        
        ok, err = check_required_option_fields(options_obj)
        if not ok:
            return None, err 
        res['general'] = options_obj['general']
        
        if 'detection' in options_obj:
            res['detection'] = options_obj['detection']
        if 'non_detection' in options_obj:
            res['non_detection'] = options_obj['non_detection']
        if 'post_detection' in options_obj:
            res['post_detection'] = options_obj['post_detection']

        return res, None
    except Exception as e:
        return None, e.__str__()


def seperate_policy(policy):
    '''
    Seperate policy to header and options

    :param policy: policy line string

    :return: two string represent header and options
    '''
    try:
        iStartBracket = -1
        iEndBracket = -1
        l = len(policy)

        for idx in range(l):
            if policy[idx] == '(':
                iStartBracket = idx if iStartBracket == -1 else iStartBracket
            if policy[l - 1 - idx] == ')':
                iEndBracket = l - 1 -idx if iEndBracket == -1 else iEndBracket

            if idx >= (l-1-idx):
                break
            if iStartBracket != -1 and iEndBracket != -1:
                break
        
        if iStartBracket == -1 or iEndBracket == -1:
            return None, 'Policy options must be enclosed in brackets'
        header = policy[:iStartBracket]
        options = policy[iStartBracket+1:iEndBracket]

        return header, options
    except Exception as e:
        return None, None
    
def parse_header(header):
    '''
    Parse header in policy to header

    :param header: string

    :return: header data if header is correct format and None vice versa
             error message if error occur or header is incorrect format and None vice versa
    '''
    try:
        header_values = header.split(' ')
        if check_action(header_values[0]) is False:
            return None, "action is incorrect format"

        if check_protocol(header_values[1]) is False:
            return None, "protocol is incorrect format"
        if check_ip(header_values[2], AddrTypes.SRC) is False:
            return None, "source address is incorrect format"

        if check_port(header_values[3], AddrTypes.SRC) is False:
            return None, "source port is incorrect format"
        if check_direction(header_values[4]) is False:
            return None, "direction is incorrect format"

        if check_ip(header_values[5], AddrTypes.DST) is False:
            return None, "destination address is incorrect format"
        if check_port(header_values[6], AddrTypes.DST) is False:
            return None, "destination port is incorrect format"

        return {
            "action": header_values[0],
            "protocol": header_values[1],
            "source_ip": header_values[2],
            "source_port": header_values[3],
            "direction": header_values[4],
            "dest_ip": header_values[5],
            "dest_port": header_values[6]
        }, None

    except Exception as e:
        return None, e.__str__()

def parse_msg(data, opts, idx, l):
    try:
        if check_enclose_bracket(data) is False:
            return None, None, "msg must be enclosed in quotation mark"
        return data.strip('"'), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_gid(data, opts, idx, l):
    try:
        if is_numeric(data) is False:
            return None, None, "gid must be an interger"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_sid(data, opts, idx, l):
    try:
        if is_numeric(data) is False:
            return None, None,"sid must be an interger"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_rev(data, opts, idx, l):
    try:
        if is_numeric(data) is False:
            return None, "rev must be an interger"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_classtype(data, opts, idx, l):
    try:
        if check_classtype(data.lower()) is False:
            return None, None, "classtype is incorrect format"
        return data.lower(), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_metadata(data, opts, idx, l):
    try:
        return data, 1, None
    except Exception as e:
        return None, None, e.__str__()


def parse_reference(data, opts, idx, l):
    try:
        if check_reference([data]) is False:
            return None, None, "reference is incorrect format"
        return data, 1, None
    except Exception as e:
        return None, None, e.__str__()
        

def parse_priority(data, opts, idx, end):
    try:
        if is_numeric(data) is False:
            return None, None, "gid must be an interger"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()


def parse_options(options):
    '''
    Parse options in policy to header

    :param options: string

    :return: options data if options is correct format and None vice versa
             error message if error occur or options is incorrect format and None vice versa
    '''
    try:
        res = {}
        opts = options.split(';')
        
        opts = opts[:-1] if opts[-1] == '' else opts
        l = len(opts)
        idx = 0
        
        while (idx < l):
            key, value = None, None
            if opts[idx].strip() in ["nocase", "rawbytes", "http_header", "file_data",
                                     "pkt_data", "base64_decode", "sameip", "ftpbounce"]:
                key, value = opts[idx].strip(), True

            else:
                [key, value], err = mSplit(opts[idx],':')
                if err != None:
                    return None, "{0} when parse '{1}'".format(err, opts[idx])
                key, value = key.strip(), value.strip()

            popt = policy_option_func(key)
            if popt['type'] != PolicyPartType.Modifier:
                val, p, err = popt['parse_func'](value, opts[idx:], idx, l)
                if err != None:
                    return None, "{0} when parse '{1}'".format(err, key)

                partStr = policy_part_str(popt['type'])
                res[partStr] = {} if partStr not in res.keys() else res[partStr]
                if key in res[partStr].keys() and popt['only_once'] is True:
                    return None, key + " need to be unique (only once)"
                
                elif key not in res[partStr].keys() and popt['only_once'] is True:
                    res[partStr][key] = val

                elif key not in res[partStr].keys() and (popt['only_once'] is False):
                    res[partStr][key] = [val]
                    
                else:
                    res[partStr][key].append(val)
                idx += p
        
        return res, None
    except Exception as e:
        return None, e.__str__()

def parse_content(content, opts, idx, end):
    res = {}
    if content[0] == '!' :
        if check_enclose_bracket(content[1:]) is False:
            return None, None, "content must be enclose in brackets"

        res['content'] = content[1:].strip('"')
        res['negative'] = True
    else:
        if check_enclose_bracket(content) is False:
            return None, None, "content must be enclose in brackets"
        
        res['content'] = content.strip('"')
        res['negative'] = False
    index = 0
    
    while index < len(opts):
        index += 1
        key, value = None, None
        
        if opts[index].strip() in bool_options:
            if opts[index].strip() != 'fast_pattern':
                key, value = opts[index].strip(), True
            else:
                key, value = opts[index].strip(), 'True'
                
        else:
            [key, value], err = mSplit(opts[index],':')
            if err != None:
                return None, None, "{0} when parse '{1}'".format(err, opts[index])
            key, value = key.strip(), value.strip()
            
        if key not in modifiers['content']:
            break

        res['modifiers'] = {}
        mopt = modifier_option_func(key)
        if mopt is None:
            res['modifiers'][key] = value
            
        else:
            val, err = mopt['parse_func'](value)
            if err != None:
                return None, None, "{0} when parse '{1}'".format(err, key)
            res['modifiers'][key] = val

    if 'modifiers' in res:
        if check_content_modifiers(res['modifiers']) is False:
            return None, None, "content modifiers is incorrect format"
        
    return res, index, None

def parse_pcontent(data, opts, idx, end):
    res = {}
    if data[0] == '!' :
        if check_enclose_bracket(data[1:]) is False:
            return None, None, "content must be enclose in brackets"

        res['protected_content'] = data[1:].strip('"')
        res['negative'] = True
    else:
        if check_enclose_bracket(data) is False:
            return None, None, "content must be enclose in brackets"
        
        res['protected_content'] = data.strip('"')
        res['negative'] = False
    index = 0
    
    while index < len(opts):
        index += 1
        key, value = None, None
        
        if opts[index].strip() in bool_options:
            if opts[index].strip() != 'fast_pattern':
                key, value = opts[index].strip(), True
            else:
                key, value = opts[index].strip(), 'True'
                
        else:
            [key, value], err = mSplit(opts[index],':')
            if err != None:
                return None, None, "{0} when parse '{1}'".format(err, opts[index])
            key, value = key.strip(), value.strip()
            
            

        if key not in modifiers['protected_content']:
            break

        res['modifiers'] = {}
        mopt = modifier_option_func(key)
        if mopt is None:
            res['modifiers'][key] = value
            
        else:
            val, err = mopt['parse_func'](value)
            if err != None:
                return None, None, "{0} when parse '{1}'".format(err, key)
            res['modifiers'][key] = val

    if check_pcontent_modifiers(res['modifiers']) is False:
        return None, None, "content modifiers is incorrect format"
    return res, index, None

def parse_ucontent(data, opts, idx, end):
    res = {}
    if data[0] == '!' :
        if check_enclose_bracket(data[1:]) is False:
            return None, None, "content must be enclose in brackets"

        res['uricontent'] = data[1:].strip('"')
        res['negative'] = True
    else:
        if check_enclose_bracket(data) is False:
            return None, None, "content must be enclose in brackets"
        
        res['uricontent'] = data.strip('"')
        res['negative'] = False
    index = 0
    
    while index < len(opts):
        index += 1
        key, value = None, None
        
        if opts[index].strip() in bool_options:
            if opts[index].strip() != 'fast_pattern':
                key, value = opts[index].strip(), True
            else:
                key, value = opts[index].strip(), 'True'
                
        else:
            [key, value], err = mSplit(opts[index],':')
            if err != None:
                return None, None, "{0} when parse '{1}'".format(err, opts[index])
            key, value = key.strip(), value.strip()
            
        if key not in modifiers['uricontent']:
            break

        res['modifiers'] = {}
        mopt = modifier_option_func(key)
        if mopt is None:
            res['modifiers'][key] = value
            
        else:
            val, err = mopt['parse_func'](value)
            if err != None:
                return None, None, "{0} when parse '{1}'".format(err, key)
            res['modifiers'][key] = val

    return res, index, None

def parse_pcre(data, opts, idx, end):
    try:
        if check_enclose_bracket(data) is False:
            return None, None, "prce must be enclosed in quotation mark"
        return data.strip('"'), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_base64(data, opts, idx, end):
    res = {}
    if isinstance(data, str):
        res["base64_decode"] = data
        
    if idx == end:
        return None, None, "After base64_decode must have more options"
    
    if opts[1].strip() != 'base64_data':
        return None, None, "After base64_decod must have base64_data option"
    
    index = 2
    if opts[index].strip() in bool_options:
        return None, None, "After file_data must be an option in [content, protected_content, uricontent]"
    else:
        [key, value], err = mSplit(opts[index],':')
        key, value = key.strip(), value.strip()
        if key not in ["content", "protected_content", "uricontent"]:
            return None, None, "After file_data must be an option in [content, protected_content, uricontent]"
        
        if key == "content":
            tmp, p, err = parse_content(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['content'] = tmp
            index = index + p
            
        elif key == "protected_content":
            tmp, p, err = parse_pcontent(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['protected_content'] = tmp
            index += p
        else:
            tmp, p, err = parse_ucontent(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['uricontent'] = tmp
            index += p
            
        return res, index, None
    

def parse_file_data(data, opts, idx, end):
    res = {}
    index = 1
    if idx == end:
        return None, None, "After file_data must be an detection rule option"
    
    if opts[index].strip() in bool_options:
        return None, None, "After file_data must be an option in [content, protected_content, uricontent]"
    else:
        [key, value], err = mSplit(opts[index],':')
        key, value = key.strip(), value.strip()
        if key not in ["content", "protected_content", "uricontent"]:
            return None, None, "After file_data must be an option in [content, protected_content, uricontent]"
        
        if key == "content":
            tmp, p, err = parse_content(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['content'] = tmp
            index = index + p
            
        elif key == "protected_content":
            tmp, p, err = parse_pcontent(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['protected_content'] = tmp
            index += p
        else:
            tmp, p, err = parse_ucontent(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['uricontent'] = tmp
            index += p
            
        return res, index, None
 
def parse_pkt_data(data, opts, idx, end):
    res = {}
    index = 1
    if idx == end:
        return None, None, "After pkt_data must be an detection rule option"
    
    if opts[index].strip() in bool_options:
        return None, None, "After pkt_data must be an option in [content, protected_content, uricontent]"
    else:
        [key, value], err = mSplit(opts[index],':')
        key, value = key.strip(), value.strip()
        if key not in ["content", "protected_content", "uricontent"]:
            return None, None, "After file_data must be an option in [content, protected_content, uricontent]"
        
        if key == "content":
            tmp, p, err = parse_content(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['content'] = tmp
            index = index + p
            
        elif key == "protected_content":
            tmp, p, err = parse_pcontent(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['protected_content'] = tmp
            index += p
        else:
            tmp, p, err = parse_ucontent(value, opts[index:], index, end)
            if err:
                return None, None, err
            res['uricontent'] = tmp
            index += p
            
        return res, index, None

def parse_http_encode(data, opts, idx, end):
    return data.strip(), 1, None

def parse_urilen(data, opts, idx, end):
    return data.strip(), 1, None

def parse_isdataat(data, opts, idx, end):
    return data.strip(), 1, None

def parse_length(data):
    try:
        if is_numeric(data) is False:
            return None, "length modifier is not integer type"
        return int(data, 10), None
    except Exception as e:
        return None, e.__str__()

def parse_hash(data):
    try:
        return data.strip(), None
    except Exception as e:
        return None, e.__str__()

def parse_offset(data):
    try:
        if is_numeric(data) is False:
            return None, "offset modifier is not integer type"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()


def parse_depth(data):
    try:
        if is_numeric(data) is False:
            return None, "distance modifier is not integer type"
        return int(data, 10), None
    except Exception as e:
        return None, e.__str__()
        

def parse_distance(data):
    try:
        if is_numeric(data) is False:
            return None, "distance modifier is not integer type"
        return int(data, 10), None
    except Exception as e:
        return None, e.__str__()


def parse_within(data):
    try:
        if is_numeric(data) is False:
            return None, None, "within modifier is not integer type"
        return int(data, 10), None
    except Exception as e:
        return None, e.__str__()


def parse_fast_pattern(data):
    try:
        return data.strip(), None
    except Exception as e:
        return None, e.__str__()


def parse_byte_test(data, opts, idx, end):
    return data.strip(), 1, None

def parse_byte_jump(data, opts, idx, end):
    return data.strip(), 1, None

def parse_byte_extract(data, opts, idx, end):
    return data.strip(), 1, None

def parse_byte_math(data, opts, idx, end):
    return data.strip(), 1, None

def parse_ftpbounce(data, opts, idx, end):
    return data, opts, idx, end

def parse_asn1(data, opts, idx, end):
    return data.strip(), 1, None

def parse_cvs(data, opts, idx, end):
    return data.strip(), 1, None

def parse_frag_offset(data, opts, idx, end):
    return data.strip(), 1, None

def parse_ttl(data, opts, idx, end):
    return data.strip(), 1, None

def parse_id(data, opts, idx, end):
    try:
        if is_numeric(data) is False:
            return None, None,"id non-dection option must be an interger"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_tos(data, opts, idx, end):
    return data.strip(), 1, None

def parse_ipopts(data, opts, idx, end):
    return data.strip(), 1, None

def parse_fragbits(data, opts, idx, end):
    return data.strip(), 1, None

def parse_dsize(data, opts, idx, end):
    return data.strip(), 1, None

def parse_flags(data, opts, idx, end):
    return data.strip(), 1, None

def parse_flowbits(data, opts, idx, end):
    return data.strip(), 1, None

def parse_seq(data, opts, idx, end):
    try:
        if is_numeric(data) is False:
            return None, None,"seq non-detection option must be an integer"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()
    
def parse_ack(data, opts, idx, end):
    try:
        if is_numeric(data) is False:
            return None, None, "ack non-detection option must be an integer"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()

def parse_windows(data, opts, idx, end):
    return data.strip(), 1, None

def parse_itype(data, opts, idx, end):
    return data.strip(), 1, None

def parse_icode(data, opts, idx, end):
    return data.strip(), 1, None

def parse_icmp_id(data, opts, idx, end):
    try:
        if is_numeric(data) is False:
            return None, None, "icmp_id non-detection option must be an integer"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()
    
def parse_icmp_seq(data, opts, idx, end):
    try:
        if is_numeric(data) is False:
            return None, None, "icmp_seq non-detection option must be an integer"
        return int(data, 10), 1, None
    except Exception as e:
        return None, None, e.__str__()
    
def parse_rpc(data, opts, idx, end):
    return data.strip(), 1, None

def parse_ip_proto(data, opts, idx, end):
    return data.strip(), 1, None

def parse_sameip(data, opts, idx, end):
    return data, 1, None

def parse_stream_reassemble(data, opts, idx, end):
    return data.strip(), 1, None

def parse_stream_size(data, opts, idx, end):
    return data.strip(), 1, None

def parse_flow(data, opts, idx, end):
    try:
        if check_flow(data) is False:
            return None, None, "Flow is incorrect"
        return data.strip(), 1, None
    except Exception as e:
        return None, None, e.__str__()
    
    
def parse_logto(data, opts, idx, end):
    return data.strip(), 1, None

def parse_session(data, opts, idx, end):
    return data.strip(), 1, None

def parse_tag(data, opts, idx, end):
    return data.strip(), 1, None

def parse_detection_filter(data, opts, idx, end):
    data = data.strip()
    res = {}
    
    try:
        fields = data.split(',')
        for field in fields:
            tmp = field.strip().split(' ')
            
            if len(tmp) != 2:
                return None, None, "detection_filter post-detection option is incorrect format"
            if tmp[0] not in ["track", "count", "seconds"]:
                return None, None, "detection_filter post-detection option is incorrect format"
            
            res[tmp[0]] = tmp[1]
        return res, 1, None
    except Exception as e:
        return None, None, e.__str__()



# --------------------------------------

policy_options = [
    {"name": "msg", "required": False, "only_once": True, "type": PolicyPartType.General, "parse_func": parse_msg},
    {"name": "gid", "required": False, "only_once": True, "type": PolicyPartType.General, "parse_func": parse_gid},
    {"name": "sid", "required": True, "only_once": True, "type": PolicyPartType.General, "parse_func": parse_sid},
    {"name": "rev", "required": False, "only_once": True, "type": PolicyPartType.General, "parse_func": parse_rev},
    {"name": "classtype", "required": True, "only_once": True, "type": PolicyPartType.General, "parse_func": parse_classtype},
    {"name": "metadata", "required": False, "only_once": False, "type": PolicyPartType.General, "parse_func": parse_metadata},
    {"name": "reference", "required": False, "only_once": False, "type": PolicyPartType.General, "parse_func": parse_reference},
    {"name": "priority", "required": False, "only_once": True, "type": PolicyPartType.General, "parse_func": parse_priority},
    {"name": "content", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_content},
    {"name": "protected_content", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_pcontent},
    {"name": "http_encode", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_http_encode},
    {"name": "uricontent", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_ucontent},
    {"name": "pcre", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_pcre},
    {"name": "flow", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_flow},
    {"name": "file_data", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_file_data},
    {"name": "base64_decode", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_base64},
    {"name": "byte_test", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_byte_test},
    {"name": "byte_jump", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_byte_jump},
    {"name": "byte_extract", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_byte_extract},
    {"name": "byte_math", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_byte_math},
    {"name": "ftpbounce", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_ftpbounce},
    {"name": "asn1", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_asn1},
    {"name": "cvs", "required": False, "only_once": True, "type": PolicyPartType.Detection, "parse_func": parse_cvs},
    {"name": "frag_offset", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_frag_offset},
    {"name": "ttl", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_ttl},
    {"name": "tos", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_tos},
    {"name": "id", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_id},
    {"name": "ipopts", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_ipopts},
    {"name": "fragbits", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_fragbits},
    {"name": "dsize", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_dsize},
    {"name": "flags", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_flags},
    {"name": "flowbits", "required": False, "only_once": False, "type": PolicyPartType.NonDetection, "parse_func": parse_flowbits},
    {"name": "seq", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_seq},
    {"name": "ack", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_ack},
    {"name": "windows", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_windows},
    {"name": "itype", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_itype},
    {"name": "icode", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_icode},
    {"name": "icmp_id", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_icmp_id},
    {"name": "icmp_seq", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_icmp_seq},
    {"name": "rpc", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_rpc},
    {"name": "ip_proto", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_ip_proto},
    {"name": "sameip", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_sameip},
    {"name": "stream_reassemble", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_stream_reassemble},
    {"name": "stream_size", "required": False, "only_once": True, "type": PolicyPartType.NonDetection, "parse_func": parse_stream_size},
    {"name": "logto", "required": False, "only_once": True, "type": PolicyPartType.PostDetection, "parse_func": parse_logto},
    {"name": "session", "required": False, "only_once": True, "type": PolicyPartType.PostDetection, "parse_func": parse_session},
    {"name": "tag", "required": False, "only_once": True, "type": PolicyPartType.PostDetection, "parse_func": parse_tag},
    {"name": "detection_filter", "required": False, "only_once": True, "type": PolicyPartType.PostDetection, "parse_func": parse_detection_filter},
    {"name": "isdataat", "required": False, "only_once": False, "type": PolicyPartType.Detection, "parse_func": parse_isdataat}
]


modifier_options = [
    {"name": "length", "required": False, "parse_func": parse_length},
    {"name": "offset", "required": False, "parse_func": parse_offset},
    {"name": "distance", "required": False, "parse_func": parse_distance},
    {"name": "within", "required": False, "parse_func": parse_within},
    {"name": "fast_pattern", "required": False, "parse_func": parse_fast_pattern},
    {"name": "hash", "required": False, "parse_func": parse_hash},
    {"name": "length", "required": False, "parse_func": parse_length},
    {"name": "depth", "required": False, "parse_func": parse_depth}
]


def policy_option_func(key):
    for popt in policy_options:
        if popt['name'] == key:
            return popt
    return None

def modifier_option_func(key):
    for mopt in modifier_options:
        if mopt['name'] == key:
            return mopt
    return None

# ---------------------------------- others --------------------

def check_uploaded_rule_file(file):
    try:
        data = file.read().decode('utf-8')
        rules = data.split('\n')
        res = []
        
        messages = []
        rule_index = 0
        for rule in rules:
            if rule == '':
                continue
            
            active = rule.strip()[0] != '#'
            r = rule.strip().strip('#').strip()
            ok, err = parse_policy_obj(r)
            
            if not ok:
                messages.append("Rule {0} is incorrect format.".format(rule_index))
            rr = '# ' + r if not active else r
            
            res.append({
                "status": active,
                "rule": rr,
                "rule_index": rule_index
            })
            rule_index += 1
        
        if not res:
            messages.append("Your file doesn't have any rule")
            
        return res, messages
    except Exception as e:
        return None, e.__str__()
      
def get_rules_for_restore(file):
  try:
    if not os.path.exists(file):
      return None, "File {file} does not exist"
    f = open(file, 'r')
    data = f.read()
    f.close()
    rules = data.split('\n')
    res = []
    
    messages = []
    rule_index = 0
    for rule in rules:
        if rule == '':
            continue
        
        active = rule.strip()[0] != '#'
        r = rule.strip().strip('#').strip()
        ok, err = parse_policy_obj(r)
        if ok: 
            rr = '# ' + r if not active else r
            
            res.append({
                "status": active,
                "rule": rr,
                "rule_index": rule_index
            })
            rule_index += 1
    
    if not res:
        messages.append("No rule is accepted!")
    return res, messages
  except Exception as e:
    return None, e.__str__()
  
  
def get_blacklist_from_file(file):
  try:
    if not os.path.exists(file):
        return None, "File {file} not found"
    with open(file, 'r') as fr:
      data = fr.read().split('\n')
    blacklist = []
    for it in data:
        if it == '':
          continue
        tmp = {}
        it = it.strip()
        tmp['status'] = False if it[0] == '#' else True
        tmp['address'] = it.strip('#').strip()
        if validate_ip(tmp['address']):
          tmp['row'] = it + '\n'
          blacklist.append(tmp)
    return blacklist, None
  except Exception as e:
    return None, e.__str__()
  
def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False