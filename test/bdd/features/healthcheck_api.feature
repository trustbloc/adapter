
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@healthcheck
Feature: health check

  Scenario Outline:
    When an HTTP GET is sent to "<url>"
    Then the JSON path "status" of the response equals "success"
    Examples:
      | url                                     |
      | http://localhost:8070/healthcheck       |
      | http://localhost:8069/healthcheck       |
