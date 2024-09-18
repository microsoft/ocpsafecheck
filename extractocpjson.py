'''
This script validates the OCP JSON Web signature (location to the JWS file is in ocpsafe.json, which is
stored in the OCP safe public git repo) against the public key of the auditor, and returns the OCP 
shortform document

Revision History:
   12-1-2023  Author: Brad Williamson (brwill)   Initial Revision
'''

from OcpReportLib import ShortFormReport
import traceback
import sys
import argparse
import logging

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--publickey', type=str, required=True, help='Link to public key')
    parser.add_argument('-s', '--signedreport', type=str, required=True, help='Signed report')
    return parser.parse_args()

def main():
    args = parse_args()

    # Construct Shortform report object
    rep = ShortFormReport()

    # Read the public key
    with open(args.publickey, "rb") as f:
        pubkey = f.read()

    # Read signed report
    with open(args.signedreport, "r") as f:
        signed_report = f.read()

    try:
        decoded = rep.verify_signed_report(signed_report, pubkey)
        print(decoded)
    except Exception:
        logging.error('Could not verify signed report')


if __name__ == '__main__':
    main()
