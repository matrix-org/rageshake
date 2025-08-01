# rageshake ![Build status](https://github.com/matrix-org/rageshake/actions/workflows/build.yaml/badge.svg)

Web service which collects and serves bug reports.

rageshake requires Go version 1.23 or later.

To run it, do:

```
go build
./bin/rageshake
```

Optional parameters:

 * `-config <path>`: The path to a YAML config file; see
   [rageshake.sample.yaml](rageshake.sample.yaml) for more information.
 * `-listen <address>`: TCP network address to listen for HTTP requests
   on. Example: `:9110`.

## Issue template

It is possible to override the templates used to construct emails, and Github and Gitlab issues.
See [templates/README.md](templates/README.md) for more information.

## API Documentation

See [docs/api.md](docs/api.md) for more information.

## Data stored on disk

Each request to `POST /api/submit` results in data being written to the local disk.
A new directory is created within `./bugs` (relative to the working directory of the `rageshake` server) for
each submission; within that directory is created:
 * Any log files attached to the submission, named as chosen by the client (provided the name is moderately sensible),
   and gzipped.
 * `details.log.gz`: a gzipped text file giving metadata about the submission, in an undocumented format. Now
   deprecated, but retained for backwards compatibility with existing tooling.
 * `details.json`: Metadata about the submission, in the same format as submitted to the
   [generic webhooks](./docs/generic_webhook.md).

## Notifications

You can get notifications when a new rageshake arrives on the server.

Currently this tool supports pushing notifications as GitHub issues in a repo,
through a Slack webhook or by email, cf sample config file for how to
configure them.

### Generic Webhook Notifications

You can receive a webhook notifications when a new rageshake arrives on the server.

These requests contain all the parsed metadata, and links to the uploaded files, and any github/gitlab
issues created.

Details on the request and expected response are [available](docs/generic\_webhook.md).


## Cleanup script

A python script is provided in scripts/cleanup.py and in a
[docker container](https://github.com/orgs/matrix-org/packages/container/package/rageshake%2Fscripts).
It can be configured using the commandline options available via `cleaup.py --help`.

It can either be run via a cronjob at appropriate intervals (typically daily), or
be set to run in a continual mode with something like `--repeat-delay-hours 24`
to repeat running after approximately 24 hours.

Note that this script will scan all logs older than the smallest configured retention period,
up to the limit specified by `--max-days` or each of the days in `--days-to-check`.
This can be an IO and CPU intensive process if a large number of files are scanned.

