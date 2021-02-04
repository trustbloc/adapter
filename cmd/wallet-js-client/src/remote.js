/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import axios from 'axios';

/**
 * RemoteWalletClient contains client functions for remote wallet for storing and getting credentials .
 *
 * Communicate with remote wallet will happen using wallet bridge endpoints in adapters.
 *
 * Refer: https://github.com/trustbloc/edge-adapter/blob/main/pkg/restapi/wallet/operation/operations.go
 *
 * @class
 */
export class RemoteClient {
    constructor({user='', remoteBridge=''}){
        if (user == '') {
            throw 'user id is required for remote wallet'
        }

        if (remoteBridge == '') {
            throw 'remote wallet endpoint is required for remote wallet'
        }

        this.user = user
        this.remoteBridge = remoteBridge
    }

    // store a credential to wallet
    // @param {Object} credential in presentation format (without proof)
    async store(vp) {
        let {data} = await axios.post(this.remoteBridge, {userID: this.user,request: vp});
        return data
    }

    // get a credential from wallet
    // @param {Object} web credential request
    async get(wCredRequest) {
        let  {data} = await axios.post(this.remoteBridge, {userID: this.user,request: wCredRequest});
        return data
    }

}
