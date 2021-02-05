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
                    <div class="flex flex-col items-center">
                        <div class="font-sans font-medium text-2xl text-center" style="margin: 5%">
                            <h3 class="text-gray-600">
                                Mobile Wallet
                            </h3>
                        </div>

                        <div class="text-gray-700" style="margin: 0% 5% 0% 5%">
                            <p>
                                Please scan this QR Code to register your mobile wallet and click proceed after you register your mobile wallet.
                            </p>
                            <div class="w-full md:w-1/2 ml-auto mr-auto">
                                <img class="max-w-full rounded-lg shadow-lg" src="../assets/img/sample-qrcode.png"/>
                            </div>
                        </div>

                        <div class="flex flex-row" style="margin: 5%">
                            <md-button class="md-raised md-accent" @click="showMobilePanel=false">Cancel</md-button>
                            <md-button class="md-raised md-primary" @click="save('remote')">Proceed</md-button>
                        </div>

                        <div>
                            <div>
                                <a class="no-underline hover:underline font-bold text-blue-700"
                                   href="https://www.canada.ca/en/financial-consumer-agency/services/payment/mobile-payments/mobile-wallets.html" target="_blank">
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
                        <md-button class="md-primary" @click="showMobilePanel = true">
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

<script>
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
                showMobilePanel: false
            }
        },
        methods: {
            save: function (selected) {
                this.showDialog = false
                this.$emit('clicked', selected)
            },
        }
    }
</script>
