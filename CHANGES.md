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
