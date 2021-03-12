/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const path = require('path');
const isSnapshot = require('./package.json').dependencies.hasOwnProperty("@trustbloc-cicd/wallet-adapter-web")
const wallet_client = (isSnapshot) ? "@trustbloc-cicd/wallet-adapter-web" : "@trustbloc/wallet-adapter-web"

module.exports = {
    publicPath: "/ui",
    configureWebpack: {
        resolve: {
            alias: {
                "@trustbloc/wallet-adapter-web": path.resolve(__dirname, 'node_modules/' + wallet_client)
            }
        }
    },
}
