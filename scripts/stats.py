#!/usr/bin/env python3
import argparse
import glob
import gzip
import os
from datetime import datetime, timedelta
from typing import Dict, Iterable, List

# Stats for rageshake server output files
#
# Example usage:
#
# ./stats.py --path /home/rageshakes/store --max-days 100
#
# No dependencies required beyond a modern python3.


class Stats(object):
    def __init__(
        self,
        days_to_check: List[int],
        root_path: str,
    ):
        self.days_to_check = days_to_check
        self.root_path = root_path
        self.checked = 0

    def check_date(self, folder_name: str) -> None:
        # list folder_name for rageshakes:
        # foreach:
        files = glob.iglob(folder_name + "/[0-9]*")

        checked = 0
        for rageshake_name in files:
            checked = checked + 1
            self.check_rageshake(rageshake_name):

        print(
            f"I Checked {folder_name} for {checked} rageshakes"
        )

        self.checked = self.checked + checked

    def check_rageshake(
        self, rageshake_folder_path: str
    ) -> None:
        try:
            app_name = None
            mxid = None
            with gzip.open(rageshake_folder_path + "/details.log.gz") as details:
                for line in details.readlines():
                    parts = line.decode("utf-8").split(":", maxsplit=1)
                    if parts[0] == "Application":
                        app_name = parts[1].strip()
                    if parts[0] == "user_id":
                        mxid = parts[1].strip()
            print(f"D {rageshake_folder_path},{app_name},{mxid},{matches}")

        except FileNotFoundError as e:
            print(
                f"W Unable to open {e.filename} to check for application name. Ignoring this folder."
            )

        return False

    def stats(self) -> None:
        today = datetime.today()
        for days_ago in self.days_to_check:
            target = today - timedelta(days=days_ago)
            folder_name = target.strftime("%Y%m%d")
            self.check_date(self.root_path + "/" + folder_name)
        pass


def main():
    parser = argparse.ArgumentParser(description="Stats")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--max-days",
        dest="max_days",
        type=int,
        help="Search all days until this maximum",
    )
    group.add_argument(
        "--days-to-check",
        dest="days_to_check",
        type=str,
        help="Explicitly supply days in the past to check , eg '1,2,3,5'",
    )
    parser.add_argument(
        "--path",
        dest="path",
        type=str,
        required=True,
        help="Root path of rageshakes (eg /home/rageshakes/bugs/)",
    )

    args = parser.parse_args()
    
    days_to_check: Iterable[int] = []
    if args.max_days:
        days_to_check = range(args.max_days)
    if args.days_to_check:
        days_to_check = map(lambda x: int(x), args.days_to_check.split(","))

    stats = Stats(
        days_to_check, args.path
    )

    stats.stats()


if __name__ == "__main__":
    main()
