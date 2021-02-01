/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import * as polyfill from 'credential-handler-polyfill';

/**
 * PolyfillClient contains client functions for 'credential-handler-polyfill' for storing and getting credentials .
 *
 * Refer: https://github.com/digitalbazaar/credential-handler-polyfill
 *
 * Note:
 *  This API deals with credential handlers already registered, it doesn't provide functions for registering new credential handler.
 *
 * @class
 */
export class PolyfillClient {
    _load() {
        polyfill.loadOnce()
    }

    _isLoaded() {
        return typeof navigator.credentialsPolyfill !== 'undefined'
    }

    // store a credential to browser wallet
    // @param {Object} credential in presentation format (without proof)
    async store(vp) {
        if (!this._isLoaded()) {
            await this._load()
        }

        return await navigator.credentials.store(new WebCredential('VerifiablePresentation', vp));
    }

    // get a credential from browser wallet
    // @param {Object} web credential request
    async get(wCredRequest) {
        if (!this._isLoaded()) {
            await this._load()
        }

        return await navigator.credentials.get(wCredRequest)
    }
}
