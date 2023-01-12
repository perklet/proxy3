def read_args():
    print(args.foo)

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--foo")
args = parser.parse_args()

read_args()
