#!/usr/bin/env python3
import argparse
import glob
import gzip
import os
from datetime import datetime, timedelta
from typing import Dict, Iterable, List

# Stats script to look across all rageshakes and get data from them to determine
# app type, matching for feedback messages, etc.
#
# Use of this is mentally to run it for specific sets of days and keep the results around in a file for
# future use; rageshakes only write in the current days' folder so should be easy enough to process like this.
#
# Example usage:
#
# ./stats.py --path /home/rageshakes/store --max-days 100
#
# Explicitly written to not require dependencies beyond a modern python3, so no packaging infra exists around it.


class Stats(object):
    def __init__(
        self,
        days_to_check: List[int],
        root_path: str,
        search_term: str,
    ):
        self.days_to_check = days_to_check
        self.root_path = root_path
        self.checked = 0
        self.search_term = search_term

    def check_date(self, folder_name: str) -> None:
        # list folder_name for rageshakes:
        # foreach:
        files = glob.iglob(folder_name + "/[0-9]*")

        checked = 0
        for rageshake_name in files:
            checked = checked + 1
            self.check_rageshake(rageshake_name)

        print(
            f"I Checked {folder_name} for {checked} rageshakes"
        )

        self.checked = self.checked + checked

    def search_files(self, file_glob: str, gzipped: bool) -> bool:
        if self.search_term is None:
            return False

        files = glob.iglob(file_glob)

        for file in files:
            if gzipped:
                with gzip.open(file,'r') as filing:
                    for line in filing.readlines():
                        if self.search_term in line.decode("utf-8"):
                            return True
            else:
                with open(file,'r') as filing:
                    for line in filing.readlines():
                        if self.search_term in line.decode("utf-8"):
                            return True

        return False

    def check_rageshake(
        self, rageshake_folder_path: str
    ) -> None:
        try:
            app_name = None
            mxid = None
            with gzip.open(rageshake_folder_path + "/details.log.gz",'r') as details:
                for line in details.readlines():
                    parts = line.decode("utf-8").split(":", maxsplit=1)
                    if parts[0] == "Application":
                        app_name = parts[1].strip()
                    if parts[0] == "user_id":
                        mxid = parts[1].strip()

            matches = self.search_files(rageshake_folder_path + "/*.log.gz", True)
            matches = matches or self.search_files(rageshake_folder_path + "/*.log", False)
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
        help="root path of rageshakes (eg /home/rageshakes/bugs/)",
    )
    parser.add_argument(
        "--search-term",
        dest="search_term",
        type=str,
        help="search term to check for matches in files (eg 'feedback')",
    )

    args = parser.parse_args()

    days_to_check: Iterable[int] = []
    if args.max_days:
        days_to_check = range(args.max_days)
    if args.days_to_check:
        days_to_check = map(lambda x: int(x), args.days_to_check.split(","))

    stats = Stats(
        days_to_check, args.path, args.search_term
    )

    stats.stats()


if __name__ == "__main__":
    main()
