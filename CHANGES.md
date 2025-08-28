# 1.16.3 (2025-08-28)

### Features

- The minimum supported version of Go is now 1.23. ([\#101](https://github.com/matrix-org/rageshake/issues/101), [\#105](https://github.com/matrix-org/rageshake/issues/105))

### Bugfixes

- Fix email support to support authenticated mail with a custom port. ([\#38](https://github.com/matrix-org/rageshake/issues/38))
- Docker: build for the right target arch. ([\#106](https://github.com/matrix-org/rageshake/issues/106))

### Internal Changes

- Bump oauth2 dependency to 0.27.0. ([\#100](https://github.com/matrix-org/rageshake/issues/100))
- Bump golang.org/x/net to 0.38.0. ([\#102](https://github.com/matrix-org/rageshake/issues/102))
- Bump github.com/hashicorp/go-retryablehttp to 0.7.7. ([\#103](https://github.com/matrix-org/rageshake/issues/103))
- Switch to golangci-lint. ([\#104](https://github.com/matrix-org/rageshake/issues/104))


1.16.2 (2025-03-19)
===================

Bugfixes
--------

- `cleanup.py`: Make resilient to malformed UTF-8 in the details file. ([\#95](https://github.com/matrix-org/rageshake/issues/95))


1.16.1 (2025-03-17)
===================

Features
--------

- Add `create_time` field to webhook payload and `details.json` ([\#93](https://github.com/matrix-org/rageshake/issues/93))


1.16.0 (2025-03-17)
===================

Features
--------

- Write a file called `details.json` for each submission. ([\#92](https://github.com/matrix-org/rageshake/issues/92))


1.15.0 (2025-03-10)
===================

Features
--------

- The `/api/submit` endpoint responds with JSON when it encounters an error.
  Please read the documentation in [docs/api.md](https://github.com/matrix-org/rageshake/blob/main/docs/api.md) to learn more. ([\#90](https://github.com/matrix-org/rageshake/issues/90))


1.14.0 (2025-02-11)
===================

Features
--------

- Parse User-Agent into a human readable format and attach to the report alongside the raw UA string. ([\#86](https://github.com/matrix-org/rageshake/issues/86))
- Reject user text (problem description) matching a regex and send the reason why to the client-side. ([\#88](https://github.com/matrix-org/rageshake/issues/88))


1.13.0 (2024-05-10)
===================

Features
--------

- Add support for blocking specific app/version/label combinations. ([\#85](https://github.com/matrix-org/rageshake/issues/85))


1.12.0 (2024-03-18)
===================

Features
--------

- Allow configuration of the body of created Github/Gitlab issues via a template in the configuration file. ([\#84](https://github.com/matrix-org/rageshake/issues/84))


1.11.0 (2023-08-11)
===================

Features
--------

- Add a link to the archive containing all the logs in the issue body. ([\#81](https://github.com/matrix-org/rageshake/issues/81))


1.10.1 (2023-05-04)
===================

Bugfixes
--------

- cleanup.py: Handle --repeat-delay-hours not being passed correctly, introduced in 1.10.0 ([\#78](https://github.com/matrix-org/rageshake/issues/78))


1.10.0 (2023-05-02)
===================

Features
--------

- Add --repeat-delay-hours option to cleanup script to run persistently outside of a cronjob. ([\#72](https://github.com/matrix-org/rageshake/issues/72))
- Allow gzipped json & txt files to be uploaded as attachments to rageshakes. ([\#75](https://github.com/matrix-org/rageshake/issues/75))


Internal Changes
----------------

- Creates a new `rageshake/scripts` image with cleanup script, ensure `latest` tag is correctly applied. ([\#71](https://github.com/matrix-org/rageshake/issues/71))
- Update README.md to include json as a valid extension for file uploads. ([\#74](https://github.com/matrix-org/rageshake/issues/74))


1.9.0 (2023-03-22)
==================

VERSIONING NOTE: From this release onwards rageshake will be versioned in `x.y.z` format, not `x.y`.

Features
--------

- Add a zero-dependency python script to cleanup old rageshakes. ([\#61](https://github.com/matrix-org/rageshake/issues/61))


Internal Changes
----------------

- Update deployment process to automatically build docker containers and binaries. ([\#70](https://github.com/matrix-org/rageshake/issues/70))


1.8 (2023-01-13)
================

Features
--------

- Add config option to block unknown appplication names. ([\#67](https://github.com/matrix-org/rageshake/issues/67))


Internal Changes
----------------

- Reimplement buildkite linting and changelog in GHA. ([\#64](https://github.com/matrix-org/rageshake/issues/64))


1.7 (2022-04-14)
================

Features
--------

- Pass the prefix as a unique ID for the rageshake to the generic webhook mechanism. ([\#54](https://github.com/matrix-org/rageshake/issues/54))


1.6 (2022-02-22)
================

Features
--------

- Provide ?format=tar.gz option on directory listings to download tarball. ([\#53](https://github.com/matrix-org/rageshake/issues/53))


1.5 (2022-02-08)
================

Features
--------

- Allow upload of Files with a .json postfix. ([\#52](https://github.com/matrix-org/rageshake/issues/52))


1.4 (2022-02-01)
================

Features
--------

- Allow forwarding of a request to a webhook endpoint. ([\#50](https://github.com/matrix-org/rageshake/issues/50))


1.3 (2022-01-25)
================

Features
--------

- Add support for creating GitLab issues. Contributed by @tulir. ([\#37](https://github.com/matrix-org/rageshake/issues/37))
- Support element-android submitting logs with .gz suffix. ([\#40](https://github.com/matrix-org/rageshake/issues/40))


Bugfixes
--------

- Prevent timestamp collisions when reports are submitted within 1 second of each other. ([\#39](https://github.com/matrix-org/rageshake/issues/39))


Internal Changes
----------------

- Update minimum Go version to 1.16. ([\#37](https://github.com/matrix-org/rageshake/issues/37), [\#42](https://github.com/matrix-org/rageshake/issues/42))
- Add documentation on the types and formats of files submitted to the rageshake server. ([\#44](https://github.com/matrix-org/rageshake/issues/44))
- Build and push a multi-arch Docker image on the GitHub Container Registry. ([\#47](https://github.com/matrix-org/rageshake/issues/47))
- Add a /health endpoint that always replies with a 200 OK. ([\#48](https://github.com/matrix-org/rageshake/issues/48))


1.2 (2020-09-16)
================

Features
--------

- Add email support. ([\#35](https://github.com/matrix-org/rageshake/issues/35))


1.1 (2020-06-04)
================

Features
--------

- Add support for Slack notifications. Contributed by @awesome-manuel. ([\#28](https://github.com/matrix-org/rageshake/issues/28))


Internal Changes
----------------

- Update minimum go version to 1.11. ([\#29](https://github.com/matrix-org/rageshake/issues/29), [\#30](https://github.com/matrix-org/rageshake/issues/30))
- Replace vendored libraries with `go mod`. ([\#31](https://github.com/matrix-org/rageshake/issues/31))
- Add Dockerfile. Contributed by @awesome-manuel. ([\#32](https://github.com/matrix-org/rageshake/issues/32))
