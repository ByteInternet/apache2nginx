#!/usr/bin/env python

import argparse
from nginxconf import parse_htaccess
import os


def find_and_convert_htaccesses(path):
    nginxconfigs = [convert_htaccess(f, path) for f in _find_htaccess_files(path)]
    return "\n".join(nginxconfigs)
    #return "\nlocation / {\n    %s\n}\n" % "\n".join(nginxconfigs)


def convert_htaccess(htaccess, path_to_docroot):
    relative_location = htaccess.replace(path_to_docroot, '').replace('.htaccess', '')

    if not relative_location.startswith('/'):
        relative_location = '/' + relative_location

    with open(htaccess, 'r') as fh:
        return parse_htaccess(fh.read(), relative_location)


def _find_htaccess_files(path):
    bingo = []

    for root, dirs, files in os.walk(path):
        for name in files:
            if name == '.htaccess':
                bingo.append(os.path.join(root, name))

    return bingo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=str, help="Where do we start the search")
    args = parser.parse_args()

    print find_and_convert_htaccesses(args.root)


if __name__ == '__main__':
    main()
