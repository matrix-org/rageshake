#!/bin/bash
#
# check the go source for lint. This is run by CI, and the pre-commit hook.

# we *don't* check gofmt here, following the advice at
# https://golang.org/doc/go1.10#gofmt

set -eu

echo "golint:"
golint -set_exit_status
echo "go vet:"
go vet -vettool=$(which shadow)
echo "gocyclo:"
gocyclo -over 12 .
