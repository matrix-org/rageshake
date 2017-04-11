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

 * `-config <path>`: The path to a YAML config file; see [./rageshake.yaml] for
   more information.
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

The body of the request should be a JSON object with the following fields:

* `text`: A textual description of the problem. Included in the
  `details.log.gz` file.

* `user_agent`: Application user-agent.  Included in the `details.log.gz` file.

* `app`: Identifier for the application (eg 'riot-web').

* `version`: Application version. Included in the `details.log.gz` file.

* `logs`: an of log files. Each entry in the list should be an object with the
  following fields:

  * `id`: textual identifier for the logs. Currently ignored.
  * `lines`: log data. Lines should be separated by newline characters (encoded
    as `\n`, as normal in JSON).

* `data`: a set of arbitrary name/value strings to include in the
  `details.log.gz` file. (Note that the values must be strings; numbers,
  objects and arrays will be rejected).
