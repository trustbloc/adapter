/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

<template>
    <div>
        <md-dialog :md-close-on-esc="false" :md-click-outside-to-close="false" :md-active.sync="showDialog">
            <div class="page-container md-layout-column" style="width: 400px; height:400px; margin: 10px">

                <!-- browser tool bar-->
                <md-drawer :md-active.sync="showBrowserPanel" md-swipeable>

                    <div class="flex flex-col items-center" style="margin: 10%">
                        <div class="font-sans font-medium text-2xl text-center" style="margin: 5%">
                            <h3 class="text-gray-600">
                                Browser Wallet
                            </h3>
                        </div>

                        <div class="text-gray-700" style="margin: 5%">
                            <div>
                                <p>
                                    Please proceed with this option to select browser based digital wallet as your
                                    wallet preference.
                                </p>
                            </div>
                        </div>

                        <div class="flex flex-row" style="margin: 5%">
                            <md-button class="md-raised md-accent" @click="showBrowserPanel=false">Cancel</md-button>
                            <md-button class="md-raised md-primary" @click="save('browser')">Proceed</md-button>
                        </div>

                        <div style="margin: 5%">
                            <div>
                                <a class="no-underline hover:underline font-bold text-blue-700"
                                   href="https://w3c-ccg.github.io/credential-handler-api/" target="_blank">
                                    <i class="fas fa-info-circle text-xl"></i> Find more about browser wallet here</a>
                            </div>
                        </div>
                    </div>
                </md-drawer>

                <!-- mobile tool bar-->
                <md-drawer class="md-right" :md-active.sync="showMobilePanel">
                    <!-- error state-->
                    <div v-if="error" class="text-gray-700" style="margin: 0% 5% 0% 5%">
                        <md-empty-state
                                md-icon="devices_other"
                                md-label="Can not register your mobile wallet now."
                                md-description="Unexpected error occurred, please try again later.">
                            <md-button class="md-raised md-accent" @click="showMobilePanel=false">Cancel</md-button>
                        </md-empty-state>
                    </div>

                    <!-- valid state-->
                    <div v-else class="flex flex-col items-center">
                        <div class="font-sans font-medium text-2xl text-center" style="margin: 5%">
                            <h3 class="text-gray-600">
                                Mobile Wallet
                            </h3>
                        </div>

                        <div class="text-gray-700" style="margin: 0% 5% 0% 5%">
                            <p>
                                Please scan this QR Code to register your mobile wallet and click proceed after you
                                register your mobile wallet.
                            </p>
                            <p v-if="retry" style="color: #d73a49" >
                                <i class="fas fa-info-circle text-xl"></i>
                                failed to register your mobile device, please try again
                            </p>

                            <div>
                                <div v-if="!qrDone" class="loading-qr">
                                    <i class="animate-pulse fas fa-sync fa-spin fa-5x" id="qr-result-wait"></i>
                                </div>

                                <img class="md:w-1/2 ml-auto mr-auto rounded-lg shadow-lg" src="" id="qr-result"/>
                            </div>
                        </div>

                        <div class="flex flex-row" style="margin: 5%">
                            <md-button class="md-raised md-accent" @click="showMobilePanel=false">Cancel</md-button>
                            <md-button class="md-raised md-primary" @click="showProgress = true && save('remote')"
                                       :disabled=disableSave>Proceed
                                <md-progress-bar md-mode="indeterminate" v-if="showProgress"></md-progress-bar>
                            </md-button>
                        </div>

                        <div>
                            <div>
                                <a class="no-underline hover:underline font-bold text-blue-700"
                                   href="https://www.canada.ca/en/financial-consumer-agency/services/payment/mobile-payments/mobile-wallets.html"
                                   target="_blank">
                                    <i class="fas fa-info-circle text-xl"></i> Find more about mobile wallet here</a>
                            </div>
                        </div>
                    </div>
                </md-drawer>

                <!-- landing-->
                <md-content class="flex flex-col">

                    <div class="font-sans font-medium text-2xl text-center" style="margin: 5%">
                        <h3 class="text-gray-600">
                            Choose your Wallet Preference
                        </h3>
                    </div>

                    <div class="items-center text-gray-700" style="margin: 10%">
                        <div>
                            <p>
                                In order to connect to your digital wallet please choose one of the following wallet
                                options.
                                <br>
                                You wallet option will be remembered during your next visit to this application.
                            </p>

                        </div>
                    </div>

                    <div class="flex flex-row" style="margin: 5%">
                        <md-button class="md-primary" @click="showBrowserPanel = true">
                            <md-icon>remove_from_queue</md-icon>
                            Browser Wallet
                        </md-button>
                        <md-button class="md-primary" @click="showMobilePanel = true; fetchQR()">
                            <md-icon>send_to_mobile</md-icon>
                            Mobile Wallet
                        </md-button>
                    </div>


                    <div class="items-center" style="margin: 10%">
                        <div>
                            <a class="no-underline hover:underline font-bold text-blue-700"
                               href="https://github.com/trustbloc/edge-sandbox/blob/master/docs/demo/sandbox_nondidcomm_playground.md"
                               target="_blank">
                                <i class="fas fa-info-circle text-xl"></i> Find more about digital wallet here</a>
                        </div>
                    </div>

                </md-content>

            </div>
        </md-dialog>
    </div>
</template>
<style>
    @import "//fonts.googleapis.com/icon?family=Material+Icons";
</style>

<style lang="css">
    .loading-qr {
        padding-left: 40%;
        height: 100px;
        padding-top: 5%;
    }
</style>
<script>

    const requestAppProfile = `/wallet-bridge/request-app-profile`
    const savePreference = `/wallet-bridge/save-preferences`
    const createInvitation = `/wallet-bridge/create-invitation`

    export default {
        props: {
            user: null,
            showDialog: {
                type: Boolean,
                default: false
            },
        },
        data() {
            return {
                showBrowserPanel: false,
                showMobilePanel: false,
                showProgress: false,
                qrDone: false,
                error: false,
                retry: false,
            }
        },
        computed: {
            disableSave() {
                return this.showProgress
            }
        },
        methods: {
            save: async function (selected) {
                if (selected == 'remote') {
                    this.showProgress = true
                    this.retry = false
                    let appProfile
                    try {
                        appProfile = await this.$http.post(requestAppProfile, {
                            userID: this.user,
                            waitForConnection: true,
                            timeout: 30 * 1000000000 // 30 sec timeout
                        })
                    } catch (e) {
                        console.log('failed to remote wallet registration status', e)
                        this.retry = true
                        return
                    } finally {
                        this.showProgress = false
                    }

                    console.log('remote wallet successfully connected.', appProfile.data)
                }

                this.$http.post(savePreference, {
                    userID: this.user,
                    walletType: selected
                })
                this.showDialog = false
                this.$emit('clicked', selected)
            },
            fetchQR: async function () {
                if (this.qrDone) {
                    return
                }

                let result
                try {
                    result = await this.$http.post(createInvitation, {
                        userID: this.user,
                    })
                } catch (e) {
                    console.log('failed to fetch invitation', e)
                    this.error = true
                    this.qrDone = true
                    return
                }


                let qrResult = () => {
                    this.qrDone = true
                }

                let QRCode = require('qrcode')
                QRCode.toDataURL(result.data.url, function (err, url) {
                    let canvas = document.getElementById('qr-result')
                    canvas.src = url
                    qrResult()
                })
            }
        }
    }
</script>
