# shallot.py
# Author: Gabriel De Jesus
# Purpose: Automate the Generation of I(D/P)S rules to block TOR Exit Node IP traffic.
import filecmp, os, requests 

def main():
    getnodelist()
    create_snort_rules('torbulkexitlist')


def getnodelist():
    """Retrieves the Current TOR Exit Node List to Store Locally"""
    try:
        url = 'https://check.torproject.org/torbulkexitlist'
        r = requests.get(url)
        open('temp', 'wb').write(r.content)
        if filecmp.cmp('torbulkexitlist', 'temp'):
            print('Files are same, deleting downloaded file...')
            os.remove('temp')
        else:
            os.remove('torbulkexitlist')
            os.rename('temp','torbulkexitlist')
    except:
        print("Can't retrieve the Exit Node List")


def create_snort_rules(infile):
    f = open(infile,'r')
    lines = f.readlines()
    count = 0
    # Strips the newline character, and formats rule
    ### TODO: output this to a file, not the console
    for line in lines:
        count += 1
        print('drop tcp {} any -> any any (msg:"TOR IP Detected"; other messages and info)'.format(line.strip()))


if __name__ == "__main__":
    main()
