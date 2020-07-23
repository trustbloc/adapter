<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div class="text-center">

        <br/>
        <h2 class="blue bg-aqua text-black">Connect Wallet to the Issuer (DIDComm)</h2>
        <br/>

        <p v-if="connectWalletSuccess">Wallet Connected Successfully.
        <p style="color:red;">{{ connectWalletErr }}</p>

    </div>
</template>

<script>
    export default {
        name: 'WalletConnect',
        data() {
            return {
                connectWalletSuccess: false,
                connectWalletErr: null,
            }
        },
        created: async function () {
            const invitationUrl = "/issuer/didcomm/chapi/request?txnID=" + this.$route.query.txnID

            let chapiRequest
            await this.$http.get(invitationUrl).then(
                resp => {
                    chapiRequest = resp.data
                },
                err => {
                    console.error(`failed to retrieve didcomm invitation: url=${invitationUrl} err=${err}`)
                }
            )

            if (chapiRequest === undefined) {
                this.connectWalletErr = "Failed to Connect to Wallet."

                return;
            }

            await this.$polyfill.loadOnce()

            const connectionRequest = {
                web: {
                    VerifiablePresentation: chapiRequest
                }
            };

            console.log("chapi request : ", JSON.stringify(connectionRequest))

            const result = await navigator.credentials.get(connectionRequest);

            console.log("chapi response : ", JSON.stringify(result.data))

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

                        this.connectWalletErr = "Failed to Connect to Wallet. " + resp.data.errMessage
                        return
                    }

                    this.connectWalletSuccess = true
                    const redirectURL = resp.data.redirectURL

                    console.log(`wallet connected successfully; redirectURL=${redirectURL}`)

                    window.location.href = redirectURL
                },
                err => {
                    console.error(`failed to validate wallet response: url=${validateUrl} err=${err}`)
                    this.connectWalletErr = "Failed to Connect to Wallet."

                    return;
                }
            )
        }
    }
</script>
