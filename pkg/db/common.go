/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

func schemas() []string {
	return []string{
		sqlCreateEndUser,
		sqlCreateOidcRequest,
	}
}
