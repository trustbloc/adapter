/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {PolyfillClient} from './polyfill'

export class WalletClient {
    constructor() {
        // TODO support for only polyfill client for now
        this.wallet = new PolyfillClient()
    }

    // store a credential to wallet
    // @param {Object} credential in presentation format (without proof)
    async store(vp) {
       return this.wallet.store(vp)
    }

    // get a credential from wallet
    // @param {Object} web credential request
    async get(wCredRequest) {
        return this.wallet.get(wCredRequest)
    }
}
