#!/usr/bin/env python3
import argparse
import glob
import gzip
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Set


# Cleanup for rageshake server output files
#
# Example usage:
#
# ./cleanup.py --dry-run --path /home/rageshakes/store --max-days 100 element-auto-uisi:90
#
# No dependencies required beyond a modern python3.


class Cleanup:
    def __init__(
        self,
        limits: Dict[str, int],
        days_to_check: Iterable[int],
        dry_run: bool,
        root_path: str,
        mxids_to_exclude: List[str],
    ):
        self._limits = limits
        self._days_to_check = days_to_check
        self._dry_run = dry_run
        self._root_path = root_path
        self._mxids_to_exclude = mxids_to_exclude
        # Count of files we deleted or would delete (dry-run)
        self.deleted = 0
        # Count of files we checked
        self.checked = 0
        # Sum of bytes in files we deleted or would delete (dry-run)
        self.disk_saved = 0
        # History of how many times a given mxid saved a file.
        self.excluded_count_by_user = {mxid: 0 for mxid in mxids_to_exclude}

    def cleanup(self) -> None:
        """
        Check for rageshakes to remove according to settings
        """
        today = datetime.today()
        for days_ago in self._days_to_check:
            target = today - timedelta(days=days_ago)
            folder_name = target.strftime("%Y-%m-%d")
            applications = set()
            for name in self._limits.keys():
                if self._limits[name] < days_ago:
                    applications.add(name)
            self._check_date(self._root_path + "/" + folder_name, applications)

    def _check_date(self, folder_name: str, applications_to_delete: Set[str]) -> None:
        """
        Check all rageshakes on a given date (folder)
        """
        if len(applications_to_delete) == 0:
            print(f"W Not checking {folder_name}, no applications would be removed")
            return

        if not os.path.exists(folder_name):
            print(f"W Not checking {folder_name}, not present or not a directory")
            return

        checked = 0
        deleted = 0
        with os.scandir(folder_name) as rageshakes:
            for rageshake in rageshakes:
                rageshake_path = folder_name + os.pathsep + rageshake.name
                if rageshake.is_dir():
                    checked += 1
                    if self._check_rageshake(rageshake_path, applications_to_delete):
                        deleted += 1
                else:
                    print(
                        f"W File in rageshake tree {rageshake_path} is not a directory"
                    )

        print(
            f"I Checked {folder_name} for {applications_to_delete}, "
            f"{'would delete' if self._dry_run else 'deleted'} {deleted}/{checked} rageshakes"
        )

        self.deleted += deleted
        self.checked += checked
        # optionally delete folder if we deleted 100% of rageshakes, but for now it' s fine.

    def _check_rageshake(
        self, rageshake_folder_path: str, applications_to_delete: Set[str]
    ) -> bool:
        """
        Checks a given rageshake folder against the application and userid lists.

        If the folder matches, and dryrun mode is disabled, the folder is deleted.
        
        @returns: True if the rageshake matched, False if it was skipped.
        """
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
            if app_name in applications_to_delete:
                if mxid in self._mxids_to_exclude:
                    self.excluded_count_by_user[mxid] += 1
                else:
                    self._delete(rageshake_folder_path)
                    return True

        except FileNotFoundError as e:
            print(
                f"W Unable to open {e.filename} to check for application name. Ignoring this folder."
            )

        return False

    def _delete(self, rageshake_folder_path: str) -> None:
        """
        Delete a given rageshake folder, unless dryrun mode is enabled
        """
        files = glob.glob(rageshake_folder_path + "/*")
        for file in files:
            self.disk_saved += os.stat(file).st_size
            if self._dry_run:
                print(f"I would delete {file}")
            else:
                print(f"I deleting {file}")
                os.unlink(file)

        if self._dry_run:
            print(f"I would remove directory {rageshake_folder_path}")
        else:
            print(f"I removing directory {rageshake_folder_path}")
            os.rmdir(rageshake_folder_path)


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
        "--exclude-mxids-file",
        dest="exclude_mxids_file",
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
        parts = x.rsplit(":", 1)
        try:
            if len(parts) < 2:
                raise ValueError("missing :")
            limit = int(parts[1])
        except ValueError as e:
            print(f"E Malformed --limits argument: {e}", file=sys.stderr)
            sys.exit(1)

        application_limits[parts[0]] = limit

    days_to_check: Iterable[int] = []
    if args.max_days:
        days_to_check = range(args.max_days)
    if args.days_to_check:
        days_to_check = map(lambda x: int(x), args.days_to_check.split(","))

    mxids_to_exclude = []
    if args.exclude_mxids_file:
        with open(args.exclude_mxids_file) as file:
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
                    print(
                        f"E Unable to parse --exclude-mxids-file on line {lineno + 1}: {data}",
                        file=sys.stderr,
                    )
                    sys.exit(1)

    cleanup = Cleanup(
        application_limits, days_to_check, args.dry_run, args.path, mxids_to_exclude
    )

    cleanup.cleanup()
    print(
        f"I Deleted {cleanup.deleted} of {cleanup.checked} rageshakes, "
        f"saving {cleanup.disk_saved} bytes. Dry run? {cleanup._dry_run}"
    )
    print(f"I excluded count by user {cleanup.excluded_count_by_user}")


if __name__ == "__main__":
    main()
