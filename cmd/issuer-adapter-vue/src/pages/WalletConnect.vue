<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div>
        <wallet-preference :user="$route.query.uID" :show-dialog="showDialog" @clicked="onPreferenceUpdate"/>
        <navbar-component></navbar-component>
        <main>
            <div class="relative pt-16 pb-16 flex content-center items-center justify-center"
                 style="min-height: 5vh;">
                <div class="absolute top-0 w-full h-full bg-center gradient bg-cover"></div>
            </div>
            <section class="relative  py-24 pb-64 pt-48">

                <div class="container mx-auto px-2">
                    <div class="bottom-auto top-0 left-0 right-0 w-full absolute pointer-events-none overflow-hidden -mt-15"
                         style="height: 80px; transform: translateZ(0px);">
                    </div>
                    <div class="container mx-auto px-4">
                        <div class="items-center flex flex-wrap">
                            <div class="w-full md:w-4/12 ml-auto mr-auto px-4">
                                <img class="max-w-full rounded-lg shadow-lg" src="../assets/img/digital_wallet.jpg"/>
                            </div>
                            <div class="w-full md:w-5/12 ml-auto mr-auto px-4">
                                <div class="md:pr-12">
                                    <ul class="list-none">
                                        <li class="py-2">
                                            <div class="flex items-center">
                                                <div><span
                                                        class="text-4xl font-semibold inline-block py-1 px-2 uppercase rounded-full text-pink-600 bg-pink-200 mr-3">
                                                 <i class="fas fa-cog fa-spin text-4xl items-center"></i></span>
                                                </div>
                                                <div>
                                                    <span class="text-2xl font-bold">
                                                        Connecting Issuer to your Wallet
                                                    </span>
                                                </div>
                                            </div>
                                        </li>
                                        <li class="py-2 px-4">
                                            <div v-if="connectWalletErr">
                                                <p class="text-2xl font-bold" style="color: red">{{ connectWalletErr
                                                    }}</p>
                                            </div>

                                            <div v-else-if="waci" class="flex flex-col" style="margin: 5%">
                                                <div class="rounded-lg shadow-lg" style="padding: 10%">
                                                    <a class="no-underline hover:underline font-bold text-blue-700"
                                                       :href="redirect">
                                                        <i class="text-2xl"></i>Click here to redirect to your
                                                        wallet</a>
                                                    <p class="text-1xl text-blue-500">or scan this code from your mobile
                                                        device</p>
                                                    <img class="md:w-3/4 ml-auto mr-auto rounded-lg shadow-lg" src=""
                                                         id="qr-result"/>
                                                </div>
                                            </div>
                                        </li>
                                        <li class="py-2">
                                            <div class="flex items-center">
                                                <div>
                                                    <h4 class="text-gray-600">
                                                        Issuer adapter establishes the connection between issuer and
                                                        your digital wallet to securely save your credentials.
                                                    </h4>
                                                    <a class="no-underline hover:underline font-bold text-blue-700"
                                                       href="https://github.com/trustbloc/edge-sandbox/blob/master/docs/demo/sandbox_nondidcomm_playground.md">
                                                        <i class="fas fa-info-circle text-xl"></i> Find more about
                                                        User's wallet here</a>
                                                </div>
                                            </div>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </section>
        </main>
        <footer-component></footer-component>
    </div>
</template>

<script>
    import WalletPreference from "./WalletPreference.vue";
    import {LoadPreferenceError, WalletClient} from "@trustbloc/wallet-adapter-web";
    import NavbarComponent from "./components/Navbar.vue";
    import FooterComponent from "./components/Footer.vue";

    export default {
        name: 'WalletConnect',
        components: {
            WalletPreference,
            NavbarComponent,
            FooterComponent
        },
        data() {
            return {
                connectWalletSuccess: false,
                connectWalletErr: null,
                showDialog: false,
                waci: true,
                redirect:"",
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
            await this.prepareRequest()
        },
        methods: {
            async prepareRequest() {
                try {
                    const invitationUrl = `/issuer/didcomm/interaction/request?txnID=${this.$route.query.txnID}`
                    const {data} = await this.$http.get(invitationUrl)

                    if (data.waci) {
                        this.renderCredentialIssuanceOptions(data)
                    } else {
                        await this.sendCHAPIRequest(data)
                    }
                } catch (e) {
                    console.error(e)
                    this.connectWalletErr = 'Failed to Connect Wallet'
                }
            },
            renderCredentialIssuanceOptions(data) {
                console.log('rendering credential issuance options here !!', data)

                const {walletRedirect} = data
                this.redirect = walletRedirect
                this.waci = true

                let QRCode = require('qrcode')
                QRCode.toDataURL(walletRedirect, function (err, url) {
                    let canvas = document.getElementById('qr-result')
                    canvas.src = url
                })
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
            async sendCHAPIRequest(data) {
                this.waci = false
                const connectionRequest = {
                    web: {
                        VerifiablePresentation: data
                    }
                };

                console.log("CHAPI request : ", connectionRequest)
                const result = await this.walletClient.get(connectionRequest);
                console.log("CHAPI response : ", result ? JSON.stringify(result.data, null, 2) : '')

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
