# shallot.py
# Author: Gabriel De Jesus
# Purpose: Automate the Generation of I(D/P)S rules to block TOR Exit Node IP traffic.
import filecmp, os, requests, sys

def main():
    getnodelist()
    create_snort_rules('torbulkexitlist')
    create_iptables_rules()


def getnodelist():
    """Retrieves the Current TOR Exit Node List to Store Locally"""
    try:
        url = 'https://check.torproject.org/torbulkexitlist'
        r = requests.get(url)
        open('temp', 'wb').write(r.content)
        # Byte-by-byte comparison, unless we need to compare hash values (more expensive)...
        if filecmp.cmp('torbulkexitlist', 'temp'):
            print('Files are same, deleting downloaded file...')
            os.remove('temp')
        else:
            os.remove('torbulkexitlist')
            os.rename('temp','torbulkexitlist')
    except:
        sys.exit("Can't retrieve the Exit Node List")  

# -- Need to test these functions! -- #
def create_snort_rules(infile):
    f = open(infile,'r')
    rules = open('torexitnodes.conf', 'w')
    lines = f.readlines()
    for line in lines:
        rules.write('drop tcp {} any -> any any (msg:"TOR IP Detected"; other messages and info)'.format(line.strip()))
    rules.close()
    f.close()

def create_iptables_rules():
    try:
        os.system('for IP in $(cat torbulkexitlist); do iptables -A INPUT -s $IP/32 -d 0/0 -j DROP; done')
    except:
        sys.exit('There was a problem setting iptables rules.')


if __name__ == "__main__":
    main()
