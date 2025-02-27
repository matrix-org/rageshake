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

## Error responses

The rageshake server will respond with a specific JSON payload when encountering an error.

```json
{
    "error": "A human readable error string.",
    "errcode": "RS_UNKNOWN",
    "policy_url": "https://github.com/matrix-org/rageshake/blob/master/docs/blocked_rageshake.md"
}
```

Where the fields are as follows:

 - `error` is an error string to explain the error, in English.
 - `errcode` is a machine readable error code which can be used by clients to give a localized error.
 - `policy_url` is an optional URL that links to a reference document, which may be presented to users.

### Error codes

- `RS_UNKNOWN` is a catch-all error when the appliation does not have a specific error.
- `RS_METHOD_NOT_ALLOWED` is reported when you have used the wrong method for a service. E.g. GET instead of POST.
- `RS_DISALLOWED_APP` is reported when a report was rejected due to the report being sent from an unsupported
   app (see the `allowed_app_names` config option).
- `RS_BAD_HEADER` is reported when a header was not able to be parsed, such as `Content-Length`.
- `RS_CONTENT_TOO_LARGE` is reported when the reported content size is too large.
- `RS_BAD_CONTENT` is reported when the reports content could not be parsed.
- `RS_REJECTED` is is reported when the submission could be understood but was rejected by `rejection_conditions`.
  This is the default value, see below for more information.

In addition to these error codes, the configuration allows application developers to specify specific error codes
for report rejection under the `RS_REJECTED_*` namespace. (see the `rejection_conditions` config option). Consult the
administrator of your rageshake server in order to determine what error codes may be presented.
