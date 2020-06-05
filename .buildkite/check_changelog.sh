#!/bin/bash
#
# this script is run by buildkite to check that a changelog file exists
#
set -e

# we need 19.9 to read config from towncrier.toml
pip3 install --pre 'towncrier>19.2'
python3 -m towncrier.check
