<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div>
        <wallet-preference :user="$route.query.uID" :show-dialog="showDialog" @clicked="onPreferenceUpdate"/>
        <navbar-component></navbar-component>
        <div class="container mx-auto px-2">
            <div class="items-center flex flex-wrap">

                <div class="w-full md:w-4/12 ml-auto mr-auto px-4">
                </div>
                <div class="w-full md:w-5/12 ml-auto mr-auto px-2">
                    <div class="md:pr-12">
                        <ul class="list-none mt-6">
                            <li class="py-2">
                                <div class="flex items-center">
                                    <div>
                                        <p class="text-2xl font-bold" style="color: red">{{ connectWalletErr }}</p>
                                    </div>
                                </div>
                            </li>
                            <li class="py-2">
                                <div class="flex items-center">
                                    <div>
                                        <p class="text-2xl font-bold" v-if="connectWalletSuccess" style="color:green">
                                            <i class="fa fa-check-circle"></i>Wallet Connected Successfully.</p>
                                    </div>
                                </div>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        <footer-component></footer-component>
    </div>
</template>

<script>
    import WalletPreference from "./WalletPreference.vue";
    import {LoadPreferenceError, WalletClient} from "@trustbloc/wallet-js-client";

    export default {
        name: 'WalletConnect',
        components: {WalletPreference},
        data() {
            return {
                connectWalletSuccess: false,
                connectWalletErr: null,
                showDialog: false,
            }
        },
        created: async function () {
            this.walletClient = new WalletClient({
                user: this.$route.query.uID,
                preferenceGETURL: `/wallet-bridge/get-preferences/${this.$route.query.uID}`,
                remoteBridge: '/wallet-bridge/send-chapi-request'
            })

            try {
                await this.walletClient.init()
            } catch (e) {
                if (e instanceof LoadPreferenceError) {
                    console.debug('failed to initialize wallet selection, presenting user preference selection dialog.')
                    this.showDialog = true
                }

                console.error(e)
                this.connectWalletErr = e.message
                return
            }

            console.log('wallet client initialized successfully !')
            await this.connect()
        },
        methods: {
            async connect() {
                try {
                    await this.sendCHAPIRequest()
                } catch (e) {
                    console.error(e)
                    this.connectWalletErr = 'Failed to Connect Wallet'
                }
            },
            async onPreferenceUpdate(preference) {
                this.showDialog = false
                console.log(`re-initializing wallet client to ${preference}`)
                this.walletClient = new WalletClient({
                    user: this.$route.query.uID,
                    remoteBridge: '/wallet-bridge/send-chapi-request',
                    defaultPreference: preference
                })

                try {
                    await this.walletClient.init()
                } catch (e) {
                    console.error(e)
                    this.connectWalletErr = "Failed to connect to your wallet"
                    return
                }

                await this.connect()
            },
            async sendCHAPIRequest() {
                const invitationUrl = `/issuer/didcomm/chapi/request?txnID=${this.$route.query.txnID}`
                let chapiRequest = await this.$http.get(invitationUrl)

                const connectionRequest = {
                    web: {
                        VerifiablePresentation: chapiRequest.data
                    }
                };

                console.log("CHAPI request : ", JSON.stringify(connectionRequest))
                const result = await this.walletClient.get(connectionRequest);
                console.log("CHAPI response : ", result ? JSON.stringify(result.data): '')

                if (!result || !result.data) {
                    throw  "Failed to Connect Wallet - no response"
                }

                const validateUrl = `/connect/validate?txnID=${this.$route.query.txnID}`
                let resp = await this.$http.post(validateUrl, {walletResp: result.data})
                if (resp.status !== 200) {
                    console.error(`failed to validate wallet response: url=${validateUrl} status=${resp.status} err=${resp.data}`)
                    throw   "Failed to Connect to Wallet. " + resp.data.errMessage
                }

                this.connectWalletSuccess = true
                console.log(`wallet connected successfully; redirectURL=${resp.data.redirectURL}`)
                window.location.href = resp.data.redirectURL
            }
        }
    }
</script>
