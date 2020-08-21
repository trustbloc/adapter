/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

<template>
    <div>
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
                            <img class="max-w-full rounded-lg shadow-lg" src="../../assets/img/digital_wallet.jpg"/>
                        </div>
                        <div class="w-full md:w-5/12 ml-auto mr-auto px-2">
                            <div class="md:pr-12">
                                <i class="fas fa-sync fa-spin text-4xl items-center"></i>
                                <h3 class="text-3xl font-semibold">Connecting Issuer to User Wallet</h3>
                                <ul class="list-none mt-6">
                                    <li class="py-2">
                                        <div class="flex items-center">
                                            <div><span class="text-xs font-semibold inline-block py-1 px-2 uppercase rounded-full text-pink-600 bg-pink-200 mr-3">
                                                <i class="fas fa-fingerprint"></i></span>
                                            </div>
                                            <div>
                                                <h4 class="text-gray-600">
                                                    Issuer adapter establishes the connection between issuer and user digital wallet
                                                </h4>
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
    import NavbarComponent from "../components/Navbar.vue";
    import FooterComponent from "../components/Footer.vue";
    export default {
        name: "landing-page",
        components: {
            NavbarComponent,
            FooterComponent
        }
    }
</script>
<style scoped>
    .gradient {
        background: linear-gradient(90deg, #000428 20%, #004e92 100%);
    }
</style>
