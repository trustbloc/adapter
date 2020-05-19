
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@healthcheck
Feature: health check

  Scenario:
    When an HTTP GET is sent to "http://localhost:8070/healthcheck"
    Then the JSON path "status" of the response equals "success"
