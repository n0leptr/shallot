# shallot.py
# Author: Gabriel De Jesus
# Purpose: Automate the Generation of IDS and SIEM rules to block TOR Exit Node IP traffic.
import filecmp
import os
import requests
import pandas as pd
import sys
from genericpath import isfile


def main():
    if getnodelist():
        create_snort_rules('torbulkexitlist')
        create_iptables_rules('torbulkexitlist')
        create_splunk_lookup('torbulkexitlist')


def getnodelist():
    try:
        url = 'http://check.torproject.org/torbulkexitlist'
        r = requests.get(url)
        open('temp', 'wb').write(r.content)
        # Byte-by-byte comparison, unless we need to compare hash values (more expensive)...
        if os.path.isfile("torbulkexitlist") and filecmp.cmp('torbulkexitlist', 'temp'):  # check diff
            print("Files are the same, deleting downloaded file...")
            os.remove('temp')
            return False
        else:
            print("Downloading newest TOR Exit node list.")
            if os.path.isfile("torbulkexitlist") == False:
                os.rename('temp', 'torbulkexitlist')
            else:
                os.rename('temp', 'torbulkexitlist')
            # delete old rule files if the exist
            if os.path.isfile('torexitnodes.snort.conf'):
                os.remove('torexitnodes.snort.conf')
            if os.path.isfile('torexitnodes.iptables'):
                os.remove('torexitnodes.iptables')
            if os.path.isfile('torexitnodes.csv'):
                os.remove('torexitnodes.csv')
            return True
    except:
        sys.exit("Can't retrieve the Exit Node List")


def create_snort_rules(infile):
    f = open(infile, 'r')
    rules = open('torexitnodes.snort.conf', 'w')
    lines = f.readlines()
    for line in lines:
        rules.write(
            'drop tcp {} any -> any any (msg:"TOR IP Detected"; other messages and info)\n'.format(line.strip()))
    rules.close()
    f.close()


def create_iptables_rules(infile):
    f = open(infile, 'r')
    ipt = open('torexitnodes.iptables', 'w')
    lines = f.readlines()
    for line in lines:
        ipt.write(
            'iptables -A INPUT -s {}/32 -d 0/0 -j DROP\n'.format(line.strip()))
    ipt.close()
    f.close()


def create_splunk_lookup(infile):
    f = open(infile, 'r')
    lines = f.readlines()
    tor_ips = []
    # convert IPs in txt file to list elements for exporting to csv
    for line in lines:
        stripped = line.strip()
        tor_ips.append(stripped)
    dict = {'exitnode_ip': tor_ips}
    df = pd.DataFrame(dict)
    df.to_csv('torexitnodes.csv')
    f.close()


if __name__ == "__main__":
    main()
