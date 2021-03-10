/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require('path');
// const isSnapshot = require('./package.json').dependencies.hasOwnProperty("@trustbloc-cicd/wallet-js-client")
// const wallet_client = (isSnapshot) ? "@trustbloc-cicd/wallet-js-client" : "@trustbloc/wallet-js-client"
const wallet_client = "@trustbloc/wallet-js-client"

module.exports = {
    publicPath: "/ui",
    configureWebpack: {
        resolve: {
            alias: {
                "@trustbloc/wallet-js-client": path.resolve(__dirname, 'node_modules/' + wallet_client)
            }
        }
    },
}
