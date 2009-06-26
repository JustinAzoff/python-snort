#!/usr/bin/env python
from optparse import OptionParser
import tempfile
import shutil
import subprocess
import os
import sys

class New: #FileNotFound :-)
    pass
New = New()

def find_tests(root):
    for path, dirs, files in os.walk(root):
        for f in files:
            if f.endswith("pcap"):
                fn = os.path.join(path, f)
                yield fn
    
def get_file(path):
    f = open(path)
    data = f.read()
    f.close()
    return data

def put_file(path, contents):
    f = open(path, 'w')
    f.write(contents)
    f.close()

class SnortTester:
    def __init__(self, root_dir, config_file):
        self.root_dir    = root_dir
        self.config_file = config_file

    def get_log_from_pcap(self, pcap_file):
        log_dir = tempfile.mkdtemp(prefix='snort')
        os.chdir(self.root_dir)
        args = ['/usr/sbin/snort', '-q', '-c', self.config_file, '-l', log_dir, '-A', 'fast', '-N', '-r', pcap_file]
        print 'running', ' '.join(args)
        subprocess.call(args)

        alert_file = os.path.join(log_dir, 'alert')

        log = get_file(alert_file)
        shutil.rmtree(log_dir)
        return log

    def test_file(self, pcap_file):
        output_file = os.path.splitext(pcap_file)[0] + '.txt'
        log = self.get_log_from_pcap(pcap_file)

        if not os.path.exists(output_file):
            put_file(output_file, log)
            return New
        expected = get_file(output_file)
        
        if log == expected:
            return True

        put_file(output_file + '.new', log)
        return False

    def test_dir(self, root):
        results = []
        for t in find_tests(root):
            res = self.test_file(t)
            results.append((t, res))

        return results
    

def main():
    parser = OptionParser()
    parser.add_option("-d", "--snort-dir", dest="dir",    action="store", help="base path to snort config files")
    parser.add_option("-c", "--config",    dest="config", action="store", help="config file")
    parser.add_option('-t', "--tests",     dest="tests",  action="store", help="directory containing tests")

    (options, args) = parser.parse_args()

    if not (options.dir and options.config and options.tests):
        sys.stderr.write("Specify snort dir, config file, and test dir\n")
        parser.print_help()
        sys.exit(1)


    tester = SnortTester(options.dir, options.config)
    results = tester.test_dir(options.tests)
    print ""
    for f, res in results:
        f = f.replace(options.tests,'')
        print f, {New: 'New', False: 'FAILED', True: 'OK'}[res]

if __name__ == "__main__":
    main()
