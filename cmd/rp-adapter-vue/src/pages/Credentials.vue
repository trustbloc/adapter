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
                <div class="bottom-auto top-0 left-0 right-0 w-full absolute pointer-events-none overflow-hidden -mt-15"
                     style="height: 80px; transform: translateZ(0px);">
                </div>
                <div class="container mx-auto px-4">
                    <div class="items-center flex flex-wrap">
                        <div class="w-full md:w-4/12 ml-auto mr-auto px-4">
                            <img class="max-w-full rounded-lg shadow-lg" src="../assets/img/rp_wallet.jpg"/>
                        </div>
                        <div class="w-full md:w-5/12 ml-auto mr-auto px-4">
                            <div class="md:pr-12">
                                <ul class="list-none">
                                    <li class="py-2">
                                        <div class="flex items-center">
                                            <div><span class="text-4xl font-semibold inline-block py-1 px-2 uppercase rounded-full text-pink-600 bg-pink-200 mr-3">
                                                 <i class="fas fa-cog fa-spin text-4xl items-center"></i></span>
                                            </div>
                                            <div>
                                                <h4 class="text-3xl font-bold">
                                                    RP requesting credential(s) from Wallet
                                                </h4>
                                            </div>
                                        </div>
                                    </li>
                                    <li class="py-2 px-4">
                                        <div>
                                            <p class="text-2xl font-bold" style="color: red">{{ connectWalletErr }}</p>
                                        </div>
                                    </li>
                                    <li class="py-2 px-4">
                                        <div class="flex items-center">
                                        <div>
                                            <a class="no-underline hover:underline font-bold text-blue-700"
                                               href="https://github.com/trustbloc/edge-sandbox/blob/master/docs/demo/sandbox_nondidcomm_playground.md">
                                                <i class="fas fa-info-circle text-xl"></i>  Find more about User's wallet here</a>
                                        </div>
                                        </div>
                                    </li>
                                </ul>
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
    import NavbarComponent from "./components/Navbar.vue";
    import FooterComponent from "./components/Footer.vue";
    import WalletPreference from "./WalletPreference.vue";
    import {LoadPreferenceError, WalletClient} from "@trustbloc/wallet-adapter-web";

    export default {
        name: 'credentials',
        components: {
            NavbarComponent,
            FooterComponent,
            WalletPreference
        },
        created: async function() {
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
            await this.requestCredentials()
        },
        data() {
            return {
                presentationRequest: null,
                connectWalletErr: null,
                showDialog: false,
            }
        },
        methods: {
            async requestCredentials(){
                try {
                    await this.sendCHAPRequest()
                } catch (e) {
                    console.error(e)
                    this.connectWalletErr = 'Failed to Connect Wallet'
                }
            },
            async sendCHAPRequest() {
                await this.getRequestForPresentation()
                const credentialQuery = {
                    web: {
                        VerifiablePresentation: {
                            query: [
                                {
                                    type: "PresentationExchange",
                                    credentialQuery: this.presentationRequest.pd

                                },
                                {
                                    type: "DIDConnect",
                                    invitation: this.presentationRequest.invitation,
                                    credentials: this.presentationRequest.credentials
                                }
                            ]
                        }
                    }
                }
                console.log("rp-adapter: chapi request: " + JSON.stringify(credentialQuery, undefined, 4))

                const webCredential = await this.walletClient.get(credentialQuery)
                if (!webCredential) {
                    console.error("no webcredential received from wallet!")
                }
                console.log("received from user: " + JSON.stringify(webCredential))
                await this.requestPresentationValidation(webCredential)
                const redirectURL = await this.validationResult(this.presentationRequest.invitation["@id"])
                // redirect user
                console.log(`redirecting user to ${redirectURL}`)
                window.location.replace(redirectURL)
            },
            async getRequestForPresentation() {
                const handle = this.$route.query.h
                console.info(`using handle: ${handle}`)
                await this.$http.get(`/presentations/create?h=${handle}`).then(
                    resp => {
                        this.presentationRequest = resp.data
                    },
                    err => {
                        console.error(`failed to retrieve presentation-definitions: ${err}`)
                        throw err
                    }
                )
            },
            async requestPresentationValidation(presentation) {
                if (!presentation || !presentation.data) {
                    throw new Error("user did not submit a proper web credential")
                }
                const request = {
                    invID: this.presentationRequest.invitation["@id"],
                    vp: presentation.data
                }
                await this.$http.post(`/presentations/handleResponse`, request).then(
                    () => {
                        console.log(`submitted presentation for evaluation`)
                    },
                    err => {
                        console.error(`failed to submit presentation for validation: ${err}`)
                        throw err
                    }
                )
            },
            async validationResult(handle) {
                const sleep = async ms => {
                    return new Promise(res => setTimeout(res, ms))
                }

                let redirectURL = ""

                for (let i = 0; i < 40; i++) {
                    await this.$http.get(`/presentations/result?h=${handle}`).then(
                        resp => {
                            redirectURL = resp.data.redirectURL
                        },
                        err => {
                            console.error(`got error response while waiting for results: ${err}`)
                        }
                    )

                    if (redirectURL.length > 0) {
                        break
                    }

                    await sleep(500)
                }

                if (redirectURL.length === 0) {
                    throw new Error("timeout waiting for presentation evaluation")
                }

                return redirectURL
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

                await this.requestCredentials()
            },
        }
    }
</script>
<style scoped>
    .gradient {
        background: linear-gradient(90deg, #000428 20%, #004e92 100%);
    }
</style>
