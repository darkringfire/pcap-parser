import csv
import json
from pathlib import Path

import dpkt
import ipaddress

import natsort
from natsort import os_sorted, natsorted

inDir = './pcap'
outFile = 'out.csv'

counters = {}
ipCnt = {}
path = Path(inDir).resolve(True)

inFiles = os_sorted(sorted(path.glob('*.pcap*')))
print(inFiles)
inFile: Path
for inFile in inFiles:
    print(inFile)
    with inFile.open('rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # iterate packets
        for ts, pkt in pcap:
            eth = dpkt.ethernet.Ethernet(pkt)
            # select IP
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                srcIP = ipaddress.ip_address(ip.src)
                dstIP = ipaddress.ip_address(ip.dst)
                # select TCP
                if ip.p != dpkt.ip.IP_PROTO_TCP or not hasattr(ip, 'tcp'):
                    continue
                tcp = ip.tcp
                # select PUSH and ACK
                if not (tcp.flags & dpkt.tcp.TH_ACK and tcp.flags & dpkt.tcp.TH_PUSH):
                    continue
                # if tcp.dport not in {25, 443, 3333}:
                #     continue
                # select data length and first symbol '{'
                if len(tcp.data) == 0 or tcp.data[0:1] != b'{':
                    continue
                # iterate parts of data packet
                for dataPart in tcp.data.split(b'\n'):
                    if len(dataPart) > 0:
                        try:
                            data = json.loads(dataPart)
                            # select method 'mining.submit'
                            if data.get('method') != 'mining.submit':
                                continue
                            srcIPKey = srcIP.exploded
                            dstIPKey = dstIP.exploded
                            param = data.get('params')[0]
                            subKey = (param, dstIPKey)
                            if srcIPKey not in counters.keys():
                                counters[srcIPKey] = {}
                            counters[srcIPKey][subKey] = counters[srcIPKey].get(subKey, 0) + 1
                        except json.decoder.JSONDecodeError:
                            # print('JSON Error:', srcIP.exploded, dataPart)
                            pass
                        except UnicodeDecodeError:
                            # print('Decode Error:', srcIP.exploded, dataPart)
                            pass

print('Parsing completed')
with Path(outFile).open('w', newline='') as csvFile:
    csvWriter = csv.writer(csvFile, dialect='excel')
    for key_ip, subKey_val in natsorted(counters.items()):
        for subKey_ip_name, val in subKey_val.items():
            print([key_ip, *subKey_ip_name, val])
            csvWriter.writerow([key_ip, *subKey_ip_name, val])
