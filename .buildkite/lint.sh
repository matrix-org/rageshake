#!/bin/sh

set -e

cd `dirname $0`/..

go get golang.org/x/lint/golint
go get github.com/fzipp/gocyclo

exec ./hooks/pre-commit
