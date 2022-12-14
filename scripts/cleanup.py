#!/usr/bin/env python3
import argparse
import glob
import gzip
import os
from datetime import datetime, timedelta
from typing import Dict, Iterable, List

# Cleanup for rageshake server output files
#
# Example usage:
#
# ./cleanup.py --dry-run --path /home/rageshakes/store --max-days 100 element-auto-uisi:90
#
# No dependencies required beyond a modern python3.


class Cleanup(object):
    def __init__(
        self,
        limits: Dict[str, int],
        days_to_check: List[int],
        dry_run: bool,
        root_path: str,
        mxids_to_exclude: List[str],
    ):
        self.dry_run = dry_run
        self.days_to_check = days_to_check
        self.limits = limits
        self.root_path = root_path
        self.deleted = 0
        self.checked = 0
        self.disk_saved = 0
        self.mxids_to_exclude = mxids_to_exclude
        self.excluded_by_user = {
            mxids_to_exclude[i]: 0 for i in range(len(mxids_to_exclude))
        }

    def check_date(self, folder_name: str, applications_to_delete: List[str]) -> None:
        if len(applications_to_delete) == 0:
            print(f"W Not checking {folder_name}, no applications would be removed")
            return

        # list folder_name for rageshakes:
        # foreach:
        files = glob.iglob(folder_name + "/[0-9]*")

        checked = 0
        deleted = 0
        for rageshake_name in files:
            checked = checked + 1
            if self.check_rageshake(rageshake_name, applications_to_delete):
                deleted = deleted + 1

        print(
            f"I Checked {folder_name} for {applications_to_delete},  deleted {deleted}/{checked} rageshakes"
        )

        self.deleted = self.deleted + deleted
        self.checked = self.checked + checked
        # optionally delete folder if we deleted 100% of rageshakes, but for now it' s fine.

    def check_rageshake(
        self, rageshake_folder_path: str, applications_to_delete: List[str]
    ) -> bool:
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
            print(f"app_name {app_name} user_id {mxid}")
            if app_name in applications_to_delete:
                if mxid in self.mxids_to_exclude:
                    self.excluded_by_user[mxid] = self.excluded_by_user[mxid] + 1
                else:
                    self.delete(rageshake_folder_path)
                    return True
            return False

        except FileNotFoundError as e:
            print(
                f"W Unable to open {e.filename} to check for application name. Ignoring this folder."
            )

        return False

    def delete(self, rageshake_folder_path: str) -> None:
        files = glob.glob(rageshake_folder_path + "/*")
        for file in files:
            self.disk_saved += os.stat(file).st_size
            if self.dry_run:
                print(f"I would delete {file}")
            else:
                print(f"I deleted {file}")
                os.unlink(file)

        if self.dry_run:
            print(f"I would remove directory {rageshake_folder_path}")
        else:
            print(f"I removing directory {rageshake_folder_path}")
            os.rmdir(rageshake_folder_path)

    def cleanup(self) -> None:
        today = datetime.today()
        for days_ago in self.days_to_check:
            target = today - timedelta(days=days_ago)
            folder_name = target.strftime("%Y%m%d")
            applications = []
            for name in self.limits.keys():
                if self.limits[name] < days_ago:
                    applications.append(name)
            self.check_date(self.root_path + "/" + folder_name, applications)
        pass


def main():
    parser = argparse.ArgumentParser(description="Cleanup rageshake files on disk")
    parser.add_argument(
        "limits",
        metavar="LIMIT",
        type=str,
        nargs="+",
        help="application_name retention limits in days (each formatted app-name:10)",
    )
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
        help="Explicitly supply days in the past to check for deletion, eg '1,2,3,5'",
    )
    parser.add_argument(
        "--exclude-mxids",
        dest="exclude_mxids",
        type=str,
        help="Supply a text file containing one mxid per line to exclude from cleanup. Blank lines and lines starting # are ignored.",
    )
    parser.add_argument(
        "--dry-run", dest="dry_run", action="store_true", help="Dry run (do not delete)"
    )
    parser.add_argument(
        "--path",
        dest="path",
        type=str,
        required=True,
        help="Root path of rageshakes (eg /home/rageshakes/bugs/)",
    )

    args = parser.parse_args()
    application_limits: Dict[str, int] = {}
    for x in args.limits:
        application_limits[x.split(":")[0]] = int(x.split(":")[1])

    days_to_check: Iterable[int] = []
    if args.max_days:
        days_to_check = range(args.max_days)
    if args.days_to_check:
        days_to_check = map(lambda x: int(x), args.days_to_check.split(","))

    mxids_to_exclude = []
    if args.exclude_mxids:
        with open(args.exclude_mxids) as file:
            for lineno, data in enumerate(file):
                data = data.strip()
                if len(data) == 0:
                    # blank line, ignore
                    pass
                elif data[0] == "#":
                    # comment, ignore
                    pass
                elif data[0] == "@":
                    # mxid
                    mxids_to_exclude.append(data)
                else:
                    raise Exception(
                        f"Unable to parse --exclude-mxids file on line {lineno + 1}: {data}"
                    )

    cleanup = Cleanup(
        application_limits, days_to_check, args.dry_run, args.path, mxids_to_exclude
    )

    cleanup.cleanup()
    print(
        f"I Deleted {cleanup.deleted} of {cleanup.checked} rageshakes. "
        f"saving {cleanup.disk_saved} bytes. Dry run? {cleanup.dry_run}"
    )
    print(f"I excluded count by user {cleanup.excluded_by_user}")


if __name__ == "__main__":
    main()
