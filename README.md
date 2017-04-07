# rageshake [![Build Status](https://travis-ci.org/matrix-org/rageshake.svg?branch=master)](https://travis-ci.org/matrix-org/rageshake)

Web service which collects and serves bug reports.

rageshake requires Go version 1.7 or later.

To run it, do:

```
go get github.com/constabulary/gb/...
gb build
GITHUB_TOKEN=<token> BUGS_USER=<user> BUGS_PASS=<password> ./bin/rageshake <port>
```

where:

 * `token` is a GitHub personal access token
   (https://github.com/settings/tokens), which will be used to create a GitHub
   issue for each report. It requires `public_repo` scope. If omitted, no
   issues will be created.
 * `user` and `password` are a username/password pair which will be required to
   access the bug report listings at `/api/listing`, via HTTP basic auth.
   If omitted, there will be *no* authentication on this access!
 * `port` is the TCP port to listen on.

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