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

                console.log("response from the wallet:", result.data)
            }
        }
    }
</script>

<style scoped>
    div {
        text-align: center;
    }
</style>
