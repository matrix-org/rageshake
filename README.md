# rageshake ![Build status](https://github.com/matrix-org/rageshake/actions/workflows/linting.yaml/badge.svg)

Web service which collects and serves bug reports.

rageshake requires Go version 1.16 or later.

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

It is possible to specify a template in the configuration file which will be used to build the
body of any issues created on Github or Gitlab, via the `issue_body_template` setting.
See [rageshake.sample.yaml](rageshake.sample.yaml) for an example.

See https://pkg.go.dev/text/template#pkg-overview for documentation of the template language.

The following properties are defined on the input (accessible via `.` or `$`):

| Name         | Type                | Description                                                                                       |
|--------------|---------------------|---------------------------------------------------------------------------------------------------|
| `ID`         | `string`            | The unique ID for this rageshake.                                                                 |
| `UserText`   | `string`            | A multi-line string containing the user description of the fault (from `text` in the submission). |
| `AppName`    | `string`            | A short slug to identify the app making the report (from `app` in the submission).                |
| `Labels`     | `[]string`          | A list of labels requested by the application.                                                    |
| `Data`       | `map[string]string` | A map of other key/value pairs included in the submission.                                        |
| `Logs`       | `[]string`          | A list of log file names.                                                                         |
| `LogErrors`  | `[]string`          | Set if there are log parsing errors.                                                              |
| `Files`      | `[]string`          | A list of other files (not logs) uploaded as part of the rageshake.                               |
| `FileErrors` | `[]string`          | Set if there are file parsing errors.                                                             |
| `ListingURL` | `string`            | Complete link to the listing URL that contains all uploaded logs.                                 |

## HTTP endpoints

The following HTTP endpoints are exposed:

### GET `/api/listing/`

Serves submitted bug reports. Protected by basic HTTP auth using the
username/password provided in the environment. A browsable list, collated by
report submission date and time.

A whole directory can be downloaded as a tarball by appending the parameter `?format=tar.gz` to the end of the URL path

### POST `/api/submit`

Submission endpoint: this is where applications should send their reports.

The body of the request should be a multipart form-data submission, with the
following form field names. (For backwards compatibility, it can also be a JSON
object, but multipart is preferred as it allows more efficient transfer of the
logs.)

* `text`: A textual description of the problem. Included in the
  `details.log.gz` file.

* `user_agent`: Application user-agent.  Included in the `details.log.gz` file.

* `app`: Identifier for the application (eg 'riot-web'). Should correspond to a
  mapping configured in the configuration file for github issue reporting to
  work.

* `version`: Application version. Included in the `details.log.gz` file.

* `label`: Label to attach to the github issue, and include in the details file.

  If using the JSON upload encoding, this should be encoded as a `labels` field,
  whose value should be a list of strings.

* `log`: a log file, with lines separated by newline characters. Multiple log
  files can be included by including several `log` parts.

  If the log is uploaded with a filename `name.ext`, where `name` contains only
  alphanumerics, `.`, `-` or `_`, and `ext` is one of `log` or `txt`, then the
  file saved to disk is based on that. Otherwise, a suitable name is
  constructed.

  If using the JSON upload encoding, the request object should instead include
  a single `logs` field, which is an array of objects with the following
  fields:

    * `id`: textual identifier for the logs. Used as the filename, as above.
    * `lines`: log data. Newlines should be  encoded as `\n`, as normal in JSON).

  A summary of the current log file formats that are uploaded for `log` and
  `compressed-log`  is [available](docs/submitted_reports.md).

* `compressed-log`: a gzipped logfile. Decompressed and then treated the same as
  `log`.

  Compressed logs are not supported for the JSON upload encoding.
  
  A summary of the current log file formats that are uploaded for `log` and
  `compressed-log` is [available](docs/submitted_reports.md).

* `file`: an arbitrary file to attach to the report. Saved as-is to disk, and
  a link is added to the github issue. The filename must be in the format
  `name.ext`, where `name` contains only alphanumerics, `-` or `_`, and `ext`
  is one of `jpg`, `png`, `txt`, `json`, `txt.gz` or `json.gz`.

  Not supported for the JSON upload encoding.

* Any other form field names are interpreted as arbitrary name/value strings to
  include in the `details.log.gz` file.

  If using the JSON upload encoding, this additional metadata should insted be
  encoded as a `data` field, whose value should be a JSON map. (Note that the
  values must be strings; numbers, objects and arrays will be rejected.)

The response (if successful) will be a JSON object with the following fields:

* `report_url`: A URL where the user can track their bug report. Omitted if
  issue submission was disabled.

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

