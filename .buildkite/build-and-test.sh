#!/bin/sh
set -e

cd `dirname $0`/..

go build
go test
