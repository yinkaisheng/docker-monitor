#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import datetime
import subprocess


CodeTemplate = '''
GitCommit = "{}"
GitDate = "{}"
'''


def main(output: str = None):
    '''
    ouput: '', 'commit_hash', 'commit_date'
    '''
    os.system('git config --global log.date iso-local')
    #output = subprocess.check_output(["git", "log", "-1", "--decorate"])
    cp = subprocess.run('git log -1 --decorate', capture_output=True, text=False, shell=True)
    #print(cp.stdout)
    commit_hash = ''
    commit_date = '' # git log -1 --format="%cd" --date=format:"%Y-%m-%d %H:%M:%S"
    if cp.returncode == 0:
        for line in cp.stdout.splitlines():
            if line.startswith(b'commit'):
                commit_hash = line[6:].decode('utf-8').strip()
            elif line.startswith(b'Date:'):
                commit_date = line[5:].decode('utf-8').strip()
                break
    if output == 'commit_hash':
        print(commit_hash)
    elif output == 'commit_date':
        print(commit_date)
    else:
        print(commit_hash)
        print(commit_date)
        with open('version.py', 'wt', encoding='utf-8', newline='\n') as fout:
            fout.write(CodeTemplate.format(commit_hash, commit_date))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) == 2 else '')
