#!/bin/sh
#
# check the go source for lint. This is run by CI, and the pre-commit hook.

# we *don't* check gofmt here, following the advice at
# https://golang.org/doc/go1.10#gofmt

set -eu

golint -set_exit_status
go vet -vettool=$(which shadow)
gocyclo -over 12 .
