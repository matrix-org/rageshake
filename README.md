# rageshake [![Build Status](https://travis-ci.org/matrix-org/rageshake.svg?branch=master)](https://travis-ci.org/matrix-org/rageshake)

Web service which collects and serves bug reports.

rageshake requires Go version 1.7 or later.

To run it, do:

```
go get github.com/constabulary/gb/...
gb build
./bin/rageshake
```

Optional parameters:

 * `-config <path>`: The path to a YAML config file; see
   [rageshake.sample.yaml](rageshake.sample.yaml) for more information.
 * `-listen <address>`: TCP network address to listen for HTTP requests
   on. Example: `:9110`.

## HTTP endpoints

The following HTTP endpoints are exposed:

### GET `/api/listing/`

Serves submitted bug reports. Protected by basic HTTP auth using the
username/password provided in the environment. A browsable list, collated by
report submission date and time.

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

  If using the JSON upload encoding, the request object should instead include
  a single `logs` field, which is an array of objects with the following
  fields:

    * `id`: textual identifier for the logs. Currently ignored.
    * `lines`: log data. Newlines should be  encoded as `\n`, as normal in JSON).

* `compressed-log`: a gzipped logfile. Decompressed and then treated the same as
  `log`.

  Compressed logs are not supported for the JSON upload encoding.

* `file`: an arbitrary file to attach to the report. Saved as-is to disk, and
  a link is added to the github issue. The filename must be in the format
  `name.ext`, where `name` contains only alphanumerics, `-` or `_`, and `ext`
  is one of `jpg`, `png`, or `txt`.

  Not supported for the JSON upload encoding.

* Any other form field names are interpreted as arbitrary name/value strings to
  include in the `details.log.gz` file.

  If using the JSON upload encoding, this additional metadata should insted be
  encoded as a `data` field, whose value should be a JSON map. (Note that the
  values must be strings; numbers, objects and arrays will be rejected.)

The response (if successful) will be a JSON object with the following fields:

* `report_url`: A URL where the user can track their bug report. Omitted if
  issue submission was disabled.
