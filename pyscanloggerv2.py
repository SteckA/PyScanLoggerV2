#!/usr/bin/python

'''*******REQUIRES PIP INSTALLS******* (dpkt, pypcap, netifaces) '''
#external libraries
import dpkt, pcap, netifaces

# built-in libraries
import os
import time
import json
import socket
import argparse
import datetime
import traceback
from collections import defaultdict
from multiprocessing import Process

# interface scan interval (seconds)
IFSCAN = 60
# number of unique port hits that triggers logging
THRESHOLD = 20
# minutes before dropping packets
SCAN_TIMEOUT = 3

# TCP flag constants
URG=dpkt.tcp.TH_URG
ACK=dpkt.tcp.TH_ACK
PSH=dpkt.tcp.TH_PUSH
RST=dpkt.tcp.TH_RST
SYN=dpkt.tcp.TH_SYN
FIN=dpkt.tcp.TH_FIN

# Protocols
TCP=dpkt.tcp.TCP
UDP=dpkt.udp.UDP

# TCP flags to scan type mapping
scan_types = {
            -1: 'UDP',
            0: 'TCP NULL',
            SYN: 'TCP SYN',
            ACK: 'TCP ACK',
            FIN: 'TCP FIN',
            SYN|RST: 'TCP SYN/RST',
            SYN|FIN: 'TCP SYN/FIN',
            FIN|ACK: 'TCP FIN/ACK',
            ACK|RST: 'TCP ACK/RST',
            FIN|ACK|RST: 'TCP FIN/ACK/RST',
            SYN|ACK|RST: 'TCP FULL-CONNECT',
            URG|PSH|ACK|RST|SYN|FIN: 'TCP ALL-FLAGS',
            URG|PSH|FIN: 'TCP XMAS', URG|PSH|FIN|ACK: 'TCP XMAS'}

# returns port scan type based on mode of flags
def get_scan_type(flaglist):
    # most common flag
    flag = max(set(flaglist), key=flaglist.count)
    return scan_types.get(flag, flag)

# translates hex address to decimal ip address
def get_ip(ifname):
    return netifaces.ifaddresses(ifname)[2][0]['addr']

# whois information using arin api
def get_whois(src):
    import urllib2
    try:
        if src not in whois:
            url = 'http://whois.arin.net/rest/ip/%s' % src
            # return as json
            header = {'Accept': 'application/arin.whoisrws-v1+json'}
            req = urllib2.Request(url, None, header)
            resp = urllib2.urlopen(req)
            data = json.load(resp)
            who = data['net']['orgRef']['@name']
            whois[src] = who
            return who
        else:
            return whois[src]
    except:
        return 'Error getting whois'

# keeps track of packets (1 per interface)
class ScanLogger(object):
    def __init__(self, verbose, logfile, whois, iface=None):
        # src ip: [(timestamp, port, flags)]
        self.pktLog = defaultdict(list)
        #interface name
        self.iface = iface
        #ip addr of interface
        self.ip_addr = get_ip(iface)
        #whois flag to run
        self.whois = whois
        #print scan detections to stdout
        self.verbose = verbose
        # Log file
        try:
            self.scanlog = open(logfile,'a')
        except (IOError, OSError), (errno, strerror):
            print "Error opening scan log file %s => %s" % (logfile, strerror)
            self.scanlog = None

    # log to file/stdout
    def log(self, line):
        if self.scanlog:
            self.scanlog.write(line + '\n')
            self.scanlog.flush()

        if self.verbose:
            print '-------Scan Detected------'
            print line

    # process each packet captured
    def process(self, ts, pkt):      
        try: ip = pkt.ip
        except: return
        try:
            # ip addresses
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            # ignore outbound
            if src == self.ip_addr: return
            # non-promiscuous
            #if dst != self.ip_addr: return

            pload = ip.data
            proto = type(pload)

            if proto == TCP:
                flags = pload.flags
            elif proto == UDP:
                flags = -1
            # ignore ICMP/IGMP
            else: return

            #reference/create pktlog for src
            pktList = self.pktLog[src]

            # add packet data as tuple to list
            pktList.append((ts, ip.data.dport, flags))

            # collect unique ports
            ports = set([i[1] for i in pktList])

            # if number of unique port hits exceeds threshold then log it
            if len(ports) >= THRESHOLD:
                #get whois info if flag is set
                who = get_whois(src) if self.whois else '[disabled]'
                flags = [i[2] for i in pktList]
                # earliest packet
                earliest = min(pktList, key=lambda x:x[0])
                # convert from unix time 
                timestamp = datetime.datetime.fromtimestamp(int(earliest[0])).strftime('%Y-%m-%d %H:%M:%S')
                # convert to json for logging      
                line = json.dumps({'src': src, 'dst': dst, 'ports': list(ports), 'scan type': get_scan_type(flags), 'time': timestamp, 'whois': who})
                self.log(line)
                #clear out packets after logging
                self.pktLog[src] = []
                
        except:
            if self.verbose:
                print 'Packet processing error'
                traceback.print_exc()

    # collect packets and send off for processing
    def run(self):
        if self.iface:
            pc = pcap.pcap(name=self.iface)
        else:
            pc = pcap.pcap()

        decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
                   pcap.DLT_NULL:dpkt.loopback.Loopback,
                   pcap.DLT_EN10MB:dpkt.ethernet.Ethernet } [pc.datalink()]

        print 'listening on %s: %s' % (pc.name, pc.filter)
        for ts, pkt in pc:
            self.process(ts, decode(pkt))

# drops packets older than SCAN_TIMEOUT minutes
def clean(procs):
    while True:
        # clean every minute
        time.sleep(60)
        limit = (time.time() - SCAN_TIMEOUT * 60)
        for p in procs[1:]:
            pl = p.sl.pktLog
            for src in pl:
                for tup in pl[src]:
                    if tup[0] < limit:
                        pl[src].remove(tup)

# custom process class to store ip with process
class Proc(Process):
    def __init__(self, sl, ip=None):
        self.sl = sl
        self.ip = ip
        super(Proc, self).__init__()
    def run(self):
        self.sl.run()

def manageThreads(options, procs, ifaces):
    for iface in set(pcap.findalldevs() + ifaces):
        # ignore vm interfaces
        if iface[:2].lower() == 'vm': continue
        try:
            ip = get_ip(iface)
            # ignore loopback
            if ip[:3] == '127': continue
        # interface doesn't have ip
        except:
            for p in procs[1:]:
                # terminate thread if iface without ip is being watched
                if iface == p.sl.iface:
                    print iface, 'ip address lost'
                    p.terminate()
                    procs.remove(p)
                    ifaces.remove(iface)
        else:
            # check if interface is being watched by process
            for p in procs[1:]:
                if iface == p.sl.iface:
                    # check if interface ip has changed
                    if ip != p.ip:
                        # terminate thread listening on interface
                        p.terminate() 
                        procs.remove(p)                      
                        print iface, 'ip address changed.'                 
                    else: break
            else:
                # create scan object and give to process to run
                sl = ScanLogger(options.verbose, options.logfile, options.whois, iface)
                p = Proc(sl, ip)
                procs.append(p)
                p.start()
                # add to interfaces being watched
                ifaces.append(iface)
                print iface + ': ' + ip

def main():
    # holds list of interfaces being watched
    ifaces = []
    # holds running processes
    procs = []

    try:
        if os.geteuid() != 0:
            print "You must be super-user to run this program"
            exit(0)

        parser = argparse.ArgumentParser(description='Detects port scanning.')
        parser.add_argument("-v", "--verbose", dest="verbose", help="Prints scan detections to stdout",
                     action="store_true", default=False)
        parser.add_argument("-f", "--logfile", dest="logfile", help="Desired path of log file",
                     default="/var/log/pyscan.log", metavar='')
        parser.add_argument("-w", "--whois", dest='whois', help="Runs whois against scanner's ip",
                    action="store_true", default=False)

        options = parser.parse_args()

        # process to drop old packets
        p = Process(target=clean, args=(procs,))
        procs.append(p)
        p.start()

        # start/stops threads listening
        while True:              
            manageThreads(options, procs, ifaces)
            time.sleep(IFSCAN)

        # shouldn't reach this point
        for p in procs:
            p.join()    
        exit('Threads completed?')
    except:
        # cleanup threads
        for p in procs:
            p.terminate()
        exit("\nStopping the PyScanLogger!")

if __name__ == '__main__':
    # caches whois info
    whois = {}
    main()
       