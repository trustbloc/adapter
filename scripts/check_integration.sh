#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

TAGS=${TAGS:-all}

PWD=`pwd`
TAGS="${TAGS:all}"
cd test/bdd

echo "Running adapter integration tests with tag=$TAGS"
go test -count=1 -v -cover . -p 1 -timeout=40m $TAGS

echo "Running adapter didcomm v2 integration tests"
go test -count=1 -v -cover . -p 1 -timeout=40m -run waci_didcommv2

cd $PWD
