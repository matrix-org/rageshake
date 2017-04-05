# rageshake [![Build Status](https://travis-ci.org/matrix-org/rageshake.svg?branch=master)](https://travis-ci.org/matrix-org/rageshake)

Web service which collects and serves bug reports.

To run it, do:

```
go get github.com/constabulary/gb/...
gb build
BUGS_USER=<user> BUGS_PASS=<password> ./bin/rageshake PORT
# example:
# BUGS_USER=alice BUGS_PASS=secret ./bin/rageshake 8080
```


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

* `version`: Application version. Included in the `details.log.gz` file.

* `logs`: an of log files. Each entry in the list should be an object with the
  following fields:

  * `id`: textual identifier for the logs. Currently ignored.
  * `lines`: log data. Lines should be separated by newline characters (encoded
    as `\n`, as normal in JSON).