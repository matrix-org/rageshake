#!/bin/sh

set -e

cd `dirname $0`/..

go get golang.org/x/lint/golint
go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow
go get github.com/fzipp/gocyclo/cmd/gocyclo

/bin/sh ./scripts/lint.sh
