# -*- coding: utf-8 -*-

"""
File: util.py
Purpose: This file contains some useful and essential function utilities.

This is the applications utilities.
"""
import re
import os

import shutil
import smtplib
import socket

import struct
import redis
import json

import pwd
import grp
import os

import hashlib
from datetime import datetime, timedelta
import subprocess
import time

import jwt
import psutil
from email.mime.text import MIMEText

from settings import config
from utils.file_handler import *
from ipaddress import IPv4Network
import ipaddress

from utils.policy.policy_util import is_numeric
from utils.protocol import PROTOCOLS
import validators
from collections import defaultdict


def encode_file_name(filename):
    '''
    Encode the filename (without extension).

    :param filename: The filename.

    :return: The encoded filename.
    '''
    encoded = hashlib.sha224(filename.encode('utf8')).hexdigest()
    return encoded

def encode_filename_sha(filename):
    '''
    Encode the filename (without extension).

    :param filename: The filename.

    :return: The encoded filename.
    '''
    encoded = hashlib.sha224(filename.encode('utf8')).hexdigest()
    return encoded


def encode_filename_md5(filename):
    encoded = hashlib.md5(filename.encode('utf8')).hexdigest()
    return encoded

def encode_auth_token(user_id, user_role):
    '''
    Generate the Auth token.

    :param user_id: The user's ID to generate token

    :return:
    '''
    try:
        payload = {
            'exp': datetime.now() + timedelta(days=30, seconds=5),
            'iat': datetime.now(),
            'sub': user_id,
            'admin': user_role
        }
        return jwt.encode(
            payload,
            config.Config.SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        print(e.__str__())
        return None


def decode_auth_token(auth_token):
    """
    Validates the auth token

    :param auth_token:

    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, config.Config.SECRET_KEY)
        return payload['sub'], ''  # return the user_id
    except jwt.ExpiredSignatureError:
        return None, 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return None, 'Invalid token. Please log in again.'
    
def convert_proto_type(ip_proto):
    '''
    Convert ip_proto to protocol type

    :param ip_proto:

    :return: The name of protocol
    '''
    if ip_proto == 6:
        return "TCP"
    elif ip_proto == 17:
        return "UDP"
    else:
        return "Unknown"

def convert_ip_2_int(ip_src):
    '''
    Convert ip address string type to ip adress int type

    :param ip_src: ip address string type

    :return: ip address int type
    '''
    return struct.unpack("!I", socket.inet_aton(ip_src))[0]

def list_2_dict(dict_key, list_value, time_format=False, time_indexs=[]):
    '''
    Transform data into dictionary type

    :param dict_key: list key of dictionary

    :param list_value: list value to transform 

    :return: The dictionary
    '''
    for x in list_value:
        if len(x) != len(dict_key):
            return "Dict key size not equal list value size."

    data = []

    for value in list_value:
        tmp = {}
        for i in range(len(value)):
            if i in time_indexs:
                tmp[dict_key[i]] = normalize_time(value[i])
                
            else:
                tmp[dict_key[i]] = value[i]
        data.append(tmp)
        
    return data

def get_cpu_usage():
    '''
    Get CPUs usage of system

    :return: percentage of CPU usage
    '''
    try:
        cpus_usage = psutil.cpu_percent(interval=1, percpu=True)
        return cpus_usage, None
    except Exception as e:
        return None, e.__str__()

def get_memory_usage():
    '''
    Get Memory usage of system

    :return: Memory usage information including total memory and used memory 
    '''
    try:
        svmem = psutil.virtual_memory()
        res = {}

        res['total'] = round(svmem.total / (2 ** 30), 1) # Gb
        res['available'] = round(svmem.available / (2 ** 30), 1) # Gb
        res['used'] = round(res['total'] - res['available'], 1) # Gb
        return res, None
    except Exception as e:
        return None, e.__str__()

def get_disk_usage():
    '''
    Get Disk usage of system

    :return: Disk usage information
    '''
    try:
        total, used, free = shutil.disk_usage('/')
        res = {}
        res['total'] = round(total / (2 ** 30), 1) # Gb
        res['used'] = round(used / (2 ** 30), 1) # Gb
        res['free'] = round(free / (2 ** 30), 1) # Gb

        return res, None
    except Exception as e:
        return None, e.__str__()
    
def get_net_usage():
    '''
    Get Network band width information of system

    :return: Network band width information
    '''
    try:
        net_usage = psutil.net_io_counters(pernic=True)
        res = {}
        for nic in net_usage.keys():
            value = {}
            value['bytes_sent'] = net_usage[nic].bytes_sent
            value['bytes_recv'] = net_usage[nic].bytes_recv
            value['packets_sent'] = net_usage[nic].packets_sent
            value['packets_recv'] = net_usage[nic].packets_recv
            res[nic] = value
        return res, None
    except Exception as e:
        return None, e.__str__()


def get_net_ifaddrs():
    return psutil.net_if_addrs()


def create_dir_sensor(path):
    '''
    Create log directory
    
    :param path: log directory path
    
    :return: True if create successfully and vice versa
    '''
    try:
        ok = create_dir(path)
        if not ok:
            return False, "Fail to create directory"
        
        uid = pwd.getpwnam("snort").pw_uid
        gid = grp.getgrnam("snort").gr_gid
        os.chown(path, uid, gid)
        
        return True, None
    except Exception as e:
        return False, e.__str__()
        

def make_barnyard_waldo(path):
    try:
        p = open(path, 'a')
        p.close()
        
        uid = pwd.getpwnam("snort").pw_uid
        gid = grp.getgrnam("snort").gr_gid
        os.chown(path, uid, gid)
        
        return True, None
    except Exception as e:
        return False, e.__str__()
    
def make_barnyard_config(cfpath, hostname, interface):
    try:
        uid = pwd.getpwnam("snort").pw_uid
        gid = grp.getgrnam("snort").gr_gid
        
        ok = copy_file_to_directory('/etc/snort/barnyard2.conf', '{0}barnyard2.conf'.format(cfpath))
        if not ok:
            return False, "Fail to make barnyard2 configuration file"
        os.chown('{0}barnyard2.conf'.format(cfpath), uid, gid)
        
        fr = open('{}barnyard2.conf'.format(cfpath), 'r')
        lines = fr.readlines()
        for i in range(len(lines)):
            if re.search("config hostname:", lines[i]):
                lines[i] = "config hostname: {0}\n".format(hostname)
            if re.search("config interface:", lines[i]):
                lines[i] = "config interface: {0}\n".format(interface)
        fr.close()
        
        fw = open('{0}barnyard2.conf'.format(cfpath), 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()
    
def make_snort_config(cfpath, log_dir, home_net):
    try:
        uid = pwd.getpwnam("snort").pw_uid
        gid = grp.getgrnam("snort").gr_gid
        
        ok = copy_file_to_directory('/etc/snort/snort.conf', '{0}snort.conf'.format(cfpath))
        if ok is False:
            return False, "Fail to make snort configuration file"
        os.chown('{0}snort.conf'.format(cfpath), uid, gid)
        
        ok = copy_file_to_directory('/etc/snort/unicode.map', '{0}unicode.map'.format(cfpath))
        if ok is False:
            return False, "Fail to make unicode map file"
        os.chown('{0}unicode.map'.format(cfpath), uid, gid)
        
        ok = copy_file_to_directory('/etc/snort/gen-msg.map', '{0}gen-msg.map'.format(cfpath))
        if ok is False:
            return False, "Fail to make gen map file"
        os.chown('{0}gen-msg.map'.format(cfpath), uid, gid)
        
        ok = copy_file_to_directory('/etc/snort/sid-msg.map', '{0}sid-msg.map'.format(cfpath))
        if ok is False:
            return False, "Fail to make sid map file"
        os.chown('{0}sid-msg.map'.format(cfpath), uid, gid)
        
        snortcfg = '{0}snort.conf'.format(cfpath)
        fr = open(snortcfg, 'r')
        lines = fr.readlines()
        
        for i in range(len(lines)):
            if re.search('config logdir:', lines[i]):
                lines[i] = 'config logdir: {0}\n'.format(log_dir)
            if re.search('ipvar HOME_NET', lines[i]):
                lines[i] = 'ipvar HOME_NET {0}\n'.format(home_net)
        fr.close()
        
        fw = open(snortcfg, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None            
    except Exception as e:
        return False, e.__str__()

def check_snort_config(cfname, interface):
    try:
        passwd = subprocess.Popen(["echo", "1"], stdout=subprocess.PIPE)
        cmd = 'sudo -S snort -q -i {0} -u snort -g snort -c {1}'.format(interface, cfname)
        p = subprocess.Popen(
            cmd,
            stdin=passwd.stdout,
            
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            preexec_fn=os.setpgrp
        )
        
        time.sleep(5)
        retcode = p.poll()
        if retcode is None:
            p.terminate()
            return True, None
        
        else:
            return False, p.stderr.read().decode('utf-8')
        
    except Exception as e:
        return False, e.__str__()
    
def check_barnyard_config(cfname, log_dir):
    try:
        passwd = subprocess.Popen(["echo", "1"], stdout=subprocess.PIPE)
        p = subprocess.Popen(
            'sudo -S barnyard2 -c {0} -d {1} -f snort.u2 -w {2}barnyard2.waldo'.format(cfname, log_dir, log_dir), 
            stdin=passwd.stdout,
            stdout=subprocess.PIPE,
            
            stderr=subprocess.PIPE,
            shell=True
        )
        
        time.sleep(90)
        err = p.stderr.read()
        if err != b'':
            return False, err.decode('utf-8')
        
        p.terminate()
        return True, None
    except Exception as e:
        return False, e.__str__()
    

def start_network_service(config_dir, log_dir, interface, barnyard2):
    r = redis.Redis(host='localhost', port=6379, db=0)
    p = r.pubsub(ignore_subscribe_messages=True)
    p.subscribe('gsm-service-action-result')
    
    r.publish(
        'gsm-service',
        json.dumps({
            "action": "Start",
            "config_dir": config_dir,
            
            "log_dir": log_dir,
            "interface": interface,
            "barnyard2": barnyard2 
        })
    )
    
    for message in p.listen():
        res = json.loads(message['data'].decode('utf-8'))

        if res['action'] == 'Start':
            if res['result'] == 'Success':
                return True, res['data'], None
            if res['result'] == 'Fail':
                return False, None, res['error']
            
        if res['action'] == 'Unknown':
            return False, None, 'Fail due to Unknown response from service'
        return False, None, 'Response not for this action'
        

def stop_network_service(config_dir, log_dir, snort_pid, barnyard2_pid):
    r = redis.Redis(host='localhost', port=6379, db=0)
    p = r.pubsub(ignore_subscribe_messages=True)
    p.subscribe('gsm-service-action-result')
    
    r.publish(
        'gsm-service',
        json.dumps({
            "action": "Stop",
            "config_dir": config_dir,
            "log_dir": log_dir,
            "snort_pid": snort_pid,
            "barnyard2_pid": barnyard2_pid
        })
    )
    
    for message in p.listen():
        res = json.loads(message['data'].decode('utf-8'))

        if res['action'] == 'Stop':
            if res['result'] == 'Success':
                return True, None
            if res['result'] == 'Fail':
                return False, res['error']
            
        if res['action'] == 'Unknown':
            return False, 'Fail due to Unknown response from service'
        return False, 'Response not for this action'


def check_home_net(home_net):
    try:
        if home_net[0] == '!':
            if home_net[1:] == 'any':
                return True
            
            tmp = home_net[1:].split('/')
            if len(tmp) != 2:
                return False
            
            ip, mask = tmp
            if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address) \
                and is_numeric(mask):
                    return False
                
            if int(mask, 10) > 31 or int(mask, 10) <= 0:
                return False
            return True
        
        if home_net == 'any':
            return True
        
        tmp = home_net[1:].split('/')
        if len(tmp) != 2:
            return False
        
        ip, mask = tmp
        if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address) \
            and is_numeric(mask):
                return False
            
        if int(mask, 10) > 31 or int(mask, 10) <= 0:
            return False
        return True
    
    except Exception as e:
        print(e.__str__())
        return False
        
        
def change_home_net(home_net, cfpath):
    try:
        fr = open('{0}/snort.conf'.format(cfpath), 'r')
        lines = fr.readlines()
        fr.close()
        
        for i in range(len(lines)):
            if re.search('ipvar HOME_NET', lines[i]):
                lines[i] = 'ipvar HOME_NET {0}\n'.format(home_net)
                break
            
        fw = open('{0}/snort.conf'.format(cfpath), 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()
    

def backup_file(source_file, target_file):
    if not os.path.exists(source_file):
        return False, "File backup is not exists"
    try:
        copy_file(source_file, target_file)
        return True, None
    except Exception as e:
        return False, e.__str__()
    
    
def get_rule_file_path(file_type):
    if file_type == 'rules':
        return '/etc/snort/rules/'
    elif file_type == 'so_rules':
        return '/etc/snort/so_rules/'
    elif file_type == 'preproc_rules':
        return '/etc/snort/preproc_rules/'
    else:
        raise Exception('file_type isn\'t  correct')


def restore_rule_file(backup_file, target_file):
    if not os.path.exists(backup_file):
        return False, 'backup file is not exist'
    else:
        try:
            copy_file(backup_file, target_file)
            return True, None
        except Exception as e:
            return False, e.__str__()
        

def check_file_name(filename):
    try:
        if len(filename.split('.')) != 2:
            return False
        tmp = filename.split('.')
        if tmp[1] != 'rules':
            return False
        return True
    except Exception as e:
        return False
    
    
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# ------------------------------------ Automation ------------------------

def check_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    try:
        if(re.fullmatch(regex, email)):
            return True
        return False
    except:
        raise Exception("An error occured")
    

def test_connect(email, password):
    try:
        smtp_server = smtplib.SMTP('smtp.gmail.com:587')
        smtp_server.starttls()
        smtp_server.login(email, password)
        return True, None
    except smtplib.SMTPHeloError as smtpHErr:
        return False, "The server didn't reply properly to the HELO greeting."
    except smtplib.SMTPAuthenticationError as smtpAuthErr:
        return False, "The server didn't accept the username/password combination."
    except smtplib.SMTPNotSupportedError as smtpNotSpErr:
        return False, "The AUTH command is not supported by the server."
    except smtplib.SMTPException as smtpErr:
        return False, "No suitable authentication method was found."
    except Exception as e:
        return False, e.__str__()


def send_test_email(email, password, recipient):
    try:
        smtp_server = smtplib.SMTP('smtp.gmail.com:587')
        smtp_server.starttls()
        smtp_server.login(email, password)
        
        msg = MIMEText("""This is an email for testing automation service of gsm system""")
        msg['Subject'] = "GSM System Notification"
        msg['From'] = "GSM System"
        msg['To'] = recipient
        
        smtp_server.sendmail(email, recipient, msg.as_string())
        return True, None
    except smtplib.SMTPHeloError as smtpHErr:
        return False, "The server didn't reply properly to the HELO greeting."
    except smtplib.SMTPAuthenticationError as smtpAuthErr:
        return False, "The server didn't accept the username/password combination."
    except smtplib.SMTPNotSupportedError as smtpNotSpErr:
        return False, "The AUTH command is not supported by the server."
    except smtplib.SMTPException as smtpErr:
        return False, "No suitable authentication method was found."
    except Exception as e:
        return False, e.__str__()
# -----------------------------------   
    
def get_addrs(lines):
    try:
        res = []
        for line in lines:
            if line == '':
                continue

            if line[0] == '#':
                ok, err = check_address(line[1:].strip())
                if not ok:
                    return None, err
                
                res.append({
                    "address": line[1:].strip(),
                    "status": False
                })
            else:
                ok, err = check_address(line)
                if not ok:
                    return None, err
                
                res.append({
                    "address": line,
                    "status": True
                })

        return res, None
    except Exception as e:
        return False, e.__str__()
    
def check_address(addr):
    try:
        _ip = ipaddress.ip_address(addr)
        return True, None
    except ValueError as vErr:
        return False, vErr.__str__()
    except Exception as e:
        return False, e.__str__()
    
# ------------------------------ CNC Server ---------------------------------    
    
def cnc_2_file(cnc, file, status):
    if not os.path.exists(file):
        return False, "Cnc file not exist"
    try:
        fr = open(file, 'r')
        lines = fr.readlines()
        fr.close()
        
        if any(re.search(cnc, line) for line in lines) is True:
            return False, 'Cnc already exists'
        
        if status:
            lines.append(cnc+'\n')
        else:
            lines.append('# ' + cnc + '\n')
            
        fw = open(file, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()

def update_cnc_2_file(source_cnc, status, file):
    if not os.path.exists(file):
        return False, "Cnc file not exist"
    try:
        fr = open(file, 'r')
        lines = fr.readlines()
        fr.close()
        
        for i in range(len(lines)):
            if re.search(source_cnc, lines[i]):
                lines[i] = '# ' + source_cnc + '\n' if not status else source_cnc + '\n'
                break
            
        fw = open(file, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()
    
def delete_cnc_2_file(cnc, file):
    if not os.path.exists(file):
        return False, "Cnc file not exist"
    try:
        fr = open(file, 'r')
        lines = fr.readlines()
        fr.close()
        
        for i in range(len(lines)):
            if re.search(cnc, lines[i]):
                lines[i] = ''
                break
        
        fw = open(file, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()
    
def update_cnc_status_2_file(cnc, status, file):
    if not os.path.exists(file):
        return False, "Cnc file not exist"
    try:
        old_cnc = '# ' + cnc if status else cnc
        new_cnc = cnc if status else '# ' + cnc
        
        fr = open(file, 'r')
        lines = fr.readlines()
        fr.close()
        
        for i in range(len(lines)):
            if re.search(old_cnc, lines[i]):
                lines[i] = new_cnc + '\n'
                break
            
        fw = open(file, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()

def get_cnc_status(line):
    try:
        res = {}
        line = line.strip()
        res['status'] = False if line[0] == '#' else True
        res['address'] = line[1:].strip() if line[0] == '#' else line.strip()
        return res, None
    except Exception as e:
        return None, e.__str__()
    
# ------------------------------

def get_lines_from_fileStorage(fileS):
    try:
        data = fileS.read().decode('utf-8')
        rules = data.split('\n')
        return [rule.strip() for rule in rules]
    except Exception as e:
        print(e.__str__())
        return None


def add_2_conf(filename, file_type, status):
    try:
        path = "/etc/snort/{}.conf".format(file_type)
        
        append_data = "include " if status else "# include"
        if file_type == "rules":
            append_data += "$RULE_PATH/{}".format(filename)
        if file_type == "so_rules":
            append_data += "$SO_RULE_PATH/{}".format(filename)
        if file_type == "preproc_rules":
            append_data += "$PREPROC_RULE_PATH/{}".format(filename)
        
        fw = open(path, 'a')
        fw.write(append_data + '\n')
        fw.close()
        return True, None
    except Exception as e:
        return False, e.__str__()

def update_status_rules_file(filename, file_type, status):
    try:
        path = "/etc/snort/{}.conf".format(file_type)
        
        fr = open(path, 'r')
        lines = fr.readlines()
        fr.close()
        
        pattern = ""
        if file_type == "rules":
            pattern = "$RULE_PATH/{}".format(filename)
        if file_type == "so_rules":
            pattern = "$SO_RULE_PATH/{}".format(filename)
        if file_type == "preproc_rules":
            pattern = "$PREPROC_RULE_PATH/{}".format(filename)

        for i in range(len(lines)):
            if pattern in lines[i]:
                lines[i] = "include {}\n".format(pattern) if status else "# include {}\n".format(pattern)
                
        fw = open(path, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        print(e.__str__())
        return False, None

def update_rule_from_file(file_name, file_type, ridx, rstatus, rold, rnew):
    try:
        file_path = get_rule_file_path(file_type=file_type) + file_name
        if not os.path.exists(file_path):
            return False, "Rule File doesn't exist"
        
        fr = open(file_path, 'r')
        lines = fr.readlines()
        fr.close()
        
        for i in range(len(lines)):
            if rold in lines[i]:
                lines[i] = rnew + '\n'
                
        fw = open(file_path, 'w')
        fw.writelines(lines)
        fw.close()

        return True, None
    except Exception as e:
        return False, e.__str__()

def delete_rule_from_file(file_name, file_type, rtext, ridx, rstatus):
    try:
        file_path = get_rule_file_path(file_type=file_type) + file_name
        if not os.path.exists(file_path):
            return False, "Rule File doesn't exist"
        
        fr = open(file_path, 'r')
        lines = fr.readlines()
        fr.close()
        
        for i in range(len(lines)):
            if rtext in lines[i]:
                lines[i] = ''
                
        fw = open(file_path, 'w')
        fw.writelines(lines)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()
    
def datetime_2_int(datetime):
    try:
        res = datetime.year*10000000000
        res +=  datetime.month * 100000000
        res += datetime.day * 1000000
        res += datetime.hour * 10000
        res += datetime.minute * 100
        res += datetime.second
        return res
    except Exception as e:
        print(e.__str__())
        return None
    

# ----------------------------------------- Setup ---------------------

def check_setup_state(state):
    try:
        if state < 0 or state > 3:
            return False
        return True
    except:
        return False


def parse_settup_options(setting_type, options):
    try:
        if setting_type == 'backup':
            res = {}
            list_opts = options.strip().split(';')
            for opt in list_opts:
                res[opt.strip()] = True
            return res, None
        else:
            return None, "Type is not correct"
    except Exception as e:
        return None, e.__str__()
    

# ------------------------------------------ Log -----------------------

def log(level, user, message):
    try:
        line = ""
        line += str(datetime.now()) + '\t\t'
        line += level + '\t\t'
        line += user + '\t\t'
        line += message + '\n'
        
        fw = open(Config.LOG_PATH, 'a', encoding='utf-8')
        fw.write(line)
        fw.close()
        
    except Exception as e:
        print(e.__str__())
        

def get_log(limit=None):
    try:
        fr = open(Config.LOG_PATH, 'r')
        lines = fr.readlines()
        fr.close()
        
        return lines[len(lines) - limit - 1: ] if limit and limit < len(lines) else lines      
    except Exception as e:
        print(e.__str__())
        

def parse_log(log):
    try:
        res = {}
        fields = log.split('\t\t')
        
        res['time'] = fields[0]
        res['level'] = fields[1]
        res['user'] = fields[2]
        res['message'] = fields[3].strip()
        
        return res, None
    except Exception as e:
        return None, e.__str__()
    
    
def parse_logs(logs):
    try:
        res = []
        for log in logs:
            ok, err = parse_log(log)
            
            if not ok:
                return None, err
            res.append(ok)
            
        return res, None
    except Exception as e:
        return None, e.__str__()
    
# ----------------------------------------- Backup ------------------------

def differ_from_blacklist(fileS, fileT):
    try:
        fr = open(fileS, 'r')
        ipsS = fr.readlines()
        fr.close()
        fr = open(fileT, 'r')
        ipsT = fr.readlines()
        fr.close()
        
        dif_rm, dif_add = [], []
        
        for ip in ipsT:
            if ip.strip() != '' and ip not in ipsS:
                dif_rm.append(ip)
        
        for ip in ipsS:
            if ip.strip() != '' and ip not in ipsT:
                dif_add.append(ip) 
        return  dif_rm, dif_add, None
    except Exception as e:
        return None, None, e.__str__()

def normalize_time(time):
    return str(time)

def get_values_by_key(dict_list, key):
    values = []
    
    for dictionary in dict_list:
        if key in dictionary:
            values.append(dictionary[key])
    
    return values
  
def fill_data_monitor(data, first, last, keys):
    data = merge_dicts_by_timestamp(data, 'timestamp')
    tmp = get_values_by_key(data, 'timestamp')
    for x in range(first + 1, last + 1):
        if x not in tmp:
            t = {}
            for key in keys:
                t[key] = 0
            t['timestamp'] = x
            data.append(t)
    return sorted(data, key=lambda x: x['timestamp'])
  
def merge_dicts_by_timestamp(arr, timestamp_key):
    merged_dict = defaultdict(int)
    
    for dictionary in arr:
        timestamp_value = dictionary[timestamp_key]
        if timestamp_value not in merged_dict:
            merged_dict[timestamp_value] = dictionary
        else:
            merged_dict[timestamp_value] = merge_dicts(merged_dict[timestamp_value], dictionary)
    
    return list(merged_dict.values())

def merge_dicts(dict1, dict2):
    merged_dict = dict1.copy()
    
    for key, value in dict2.items():
        if key in merged_dict:
            merged_dict[key] += value
        else:
            merged_dict[key] = value
    
    return merged_dict

def add_rule_to_file(raw_text, active, filepath):
    if not os.path.exists(filepath):
        return False, "{0} isn't exist".format(filepath)
    rule = '# ' + raw_text if not active else raw_text
    
    fw = open(filepath, 'a')
    fw.write(rule + '\n')
    fw.close()
    return True, None
    

def protocol_2_int(protocol):
    protocol = protocol.upper()
    return int(list(PROTOCOLS.keys())[list(PROTOCOLS.values()).index(protocol)], 10)

def add_msg_2_sidmap(options):
    try:
        msgAlert = ""
        if 'msg' in options:
            msgAlert = options["msg"] 
            
        else:
            msgAlert += "GSM Alert ["
            msgAlert += str(options['gid']) if 'gid' in options else '1:'
            
            msgAlert += str(options['sid'])
            msgAlert += str(options['rev']) if 'rev' in options else ':1]'
        
        msgReference = ""
        if 'reference' in options:
            for ref in options['reference']:
                msgReference += " || " + ref
        
        sidMsg = ""
        sidMsg += str(options['sid'])
        sidMsg += " || " + msgAlert
        sidMsg += msgReference + '\n'
        
        fw = open('/etc/snort/sid-msg.map', 'a')
        fw.write(sidMsg)
        fw.close()
        
        return True, None
    except Exception as e:
        return False, e.__str__()


def priority_str_int(prior):
    if prior == "very low":
        return 0
    elif prior == "low":
        return 1
    elif prior == "medium":
        return 2
    elif prior == "high":
        return 3
    else:
        return 4

def save_rules_2_file(rules, path, overwrite):
    if not os.path.exists(path) or (os.path.exists(path) & overwrite):
        try:
            fw = open(path, 'w')
            fw.writelines(rules)
            fw.close()
            return True, None
        except Exception as e:
            return False, e.__str__()
    else:
        return False, "File {} alread exist".format(path)
            
        

def check_process_exist(pid):
    try:
        p = psutil.Process(pid)
        if p.status() not in ["zombie", "terminated"]:
            return True
        return False
    except :
        return False
        
def check_domain(domain):
    try:
        ok = validators.domain(domain)
        if ok == True:
            return True
        else:
            return False
    except:
        return False
    
def match_rule_in_file(text, choices):
    from fuzzywuzzy import process
    matches = process.extract(text, choices, limit=2)
    for _, match in matches:
        if match > 95:
            return False
    return True

def reparse_proto(data):
    try:
        key = []
        res = []
        for dt in data:
            if str(dt['protocol']) not in key:
                res.append({'protocol': str(dt['protocol']), 'count': dt['count']})
                key.append(str(dt['protocol']))
            else:
                res[key.index(dt['protocol'])]['count'] += dt['count']
        return res
    except Exception as e:
        print(e.__str__())
        return []