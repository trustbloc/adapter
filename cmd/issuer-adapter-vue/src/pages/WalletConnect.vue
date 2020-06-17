<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div class="vertical-center">
        <h1>Connect Wallet to the Issuer (DIDComm)</h1>

        <button v-on:click="connectWallet">Connect Wallet</button>

        <p style="color:red;">{{ connectWalletErr }}</p>

        <br/>
        <br/>

    </div>
</template>

<script>
    export default {
        name: 'WalletConnect',
        data() {
            return {
                connectWalletErr: null
            }
        },
        methods: {
            connectWallet: async function () {
                const invitationUrl = "/issuer/didcomm/invitation"

                let invitation
                await this.$http.get(invitationUrl).then(
                    resp => {
                        invitation = resp.data
                    },
                    err => {
                        console.error(`failed to retrieve didcomm invitation: url=${invitationUrl} err=${err}`)
                    }
                )

                if (invitation === undefined) {
                    this.connectWalletErr = "Failed to Connect Wallet."

                    return;
                }

                await this.$polyfill.loadOnce()

                const connectionRequest = {
                    web: {
                        VerifiablePresentation: {
                            query: {type: "DIDConnect"},
                            invitation: invitation
                        }
                    }
                };

                console.log("Sending credential query", connectionRequest)

                const result = await navigator.credentials.get(connectionRequest);
                console.log("DIDComm connection webcredential response:", result.data)

                if (!result || !result.data) {
                    console.error("Failed to Connect Wallet - no response")

                    this.connectWalletErr = "Failed to Connect Wallet."
                    return;
                }

                const validateUrl = "/connect/validate?txnID=" + this.$route.query.txnID
                await this.$http.post(validateUrl, {walletResp: result.data}).then(
                    resp => {
                        if (resp.status !== 200) {
                            console.error(`failed to validate wallet response: url=${validateUrl} status=${resp.status} err=${resp.data}`)

                            this.connectWalletErr = "Failed to Connect Wallet. " + resp.data.errMessage
                            return
                        }

                        console.log("wallet connected successfully")
                    },
                    err => {
                        console.error(`failed to validate wallet response: url=${validateUrl} err=${err}`)
                        this.connectWalletErr = "Failed to Connect Wallet."
                    }
                )
            }
        }
    }
</script>

<style scoped>
    div {
        text-align: center;
    }
</style>
