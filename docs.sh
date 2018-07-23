#!/bin/bash

set -e

cd docs/website
GIT_USER=nemosupremo CURRENT_BRANCH=${1:master} USE_SSH=true yarn run publish-gh-pages