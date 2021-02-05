/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import axios from 'axios';
import {PolyfillClient} from './polyfill'
import {RemoteClient} from './remote'

const walletTypes = {"browser": PolyfillClient, "remote": RemoteClient}

/**
 * WalletClient is client API for browser and remote wallets.
 *
 * Once initialized, it supports either browser or remote wallet based on initialization options .
 *
 */
export class WalletClient {
    /**
     *
     * @class WalletClient
     *
     * Can be initialized with below optional parameters
     *
     * @param user - (optional) identifier for wallet user, used to fetch wallet preferences & for remote wallet APIs.
     * @param preferencePOSTURL -  (optional) http POST URL to fetch user wallet preferences.
     * @param preferenceGETURL -  (optional) http GET URL to fetch user wallet preferences.
     * @param defaultPreference - (optional) default wallet preference when no URL fetch option is provided.
     * supported values 'browser,remote'. If provided, this option will also be used as fallback when client API fails to fetch
     * wallet preferences from http URLs.
     * @param remoteBridge - (optional, but required for Remote wallet usage) bridge URL to be used to send credential handler
     * messages to remote wallet.
     */
    constructor({user = '', preferencePOSTURL = '', preferenceGETURL = '', defaultPreference = '', remoteBridge = ''} = {}) {
        this.walletInitOpts = {user, remoteBridge}
        this.preference = getWalletPreference(user, {preferencePOSTURL, preferenceGETURL, defaultPreference})
    }

    isInitialized(){
        return this.wallet ? true : false
    }

    /** initializes wallet client based on preference type
     * @throws {LoadPreferenceError} if fails to fetch preference.
     */
    async init(){
        if (!this.wallet) {
            let walletType = walletTypes[await this.preference]
            if (!walletType) {
                throw "invalid wallet type"
            }

            this.wallet = new walletType(this.walletInitOpts)
        }
    }


    /** store a credential to wallet
     * @param {Object} credential in presentation format (without proof)
     */
    async store(vp) {
        await this.init()
        return this.wallet.store(vp)
    }

    /** get a credential from wallet
     * @param {Object} web credential request
     */
    async get(wCredRequest) {
        await this.init()
        return this.wallet.get(wCredRequest)
    }
}

export class LoadPreferenceError extends Error {
    constructor(message) {
        super(message);
        this.name = "LoadPreferenceError";
    }
}

async function getWalletPreference(user, opts) {
    const cname = `pref.wallet.type.${user}`
    let preference = findCookie(cname)

    if (preference) {
        console.log('found saved wallet preference', preference)
        return preference
    }

    try {
        if (opts.preferenceGETURL) {
            const {data} = await axios.get(opts.preferenceGETURL)
            console.debug(`choosing wallet type '${data.walletType}' based on preference fetched.`)
            preference = data.walletType
        } else if (opts.preferencePOSTURL) {
            const {data} = await axios.post(opts.preferencePOSTURL)
            console.debug(`choosing wallet type '${data.walletType}' based on preference fetched.`)
            preference = data.walletType
        } else if (opts.defaultPreference) {
            console.debug(`choosing wallet type '${opts.defaultPreference}' based on default preference.`)
            preference = opts.defaultPreference
        } else {
            throw new LoadPreferenceError('failed to select wallet type, provide at least default preference')
        }
    } catch (e) {
        console.error('failed to fetch wallet preference', e)
        if (opts.defaultPreference) {
            return opts.defaultPreference
        } else {
            throw new LoadPreferenceError('failed to fetch wallet preference')
        }
    }

    updateCookie(cname, preference)

    console.log('fetched wallet preference', preference)
    return preference
}

function findCookie(name) {
    let matches = document.cookie.split('; ').find(row => row.startsWith(name))
    return matches ? matches.split('=')[1] : ''
}

let updateCookie = (name, preference) => document.cookie = `${name}=${preference}`





