<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

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
                            <img class="max-w-full rounded-lg shadow-lg" src="../assets/img/rp_wallet.jpg"/>
                        </div>
                        <div class="w-full md:w-5/12 ml-auto mr-auto px-4">
                            <i class="fas fa-cog fa-spin text-4xl items-center"></i>
                            <div class="md:pr-12">
                                <h3 class="text-3xl font-semibold">
                                    RP requesting credential(s) from  User's Wallet</h3>
                                <ul class="list-none mt-6">
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

    export default {
        name: 'credentials',
        components: {
            NavbarComponent,
            FooterComponent
        },
        created: async function() {
            await this.$polyfill.loadOnce()
            await this.getRequestForPresentation()
            const credentialQuery = {
                web: {
                    VerifiablePresentation: {
                        query: [
                            {
                                type: "PresentationDefinitionQuery",
                                presentationDefinitionQuery: this.presentationRequest.pd

                            },
                            {
                                type: "DIDConnect",
                                invitation: this.presentationRequest.invitation
                            }
                        ]
                    }
                }
            }
            console.log("rp-adapter: chapi request: " + JSON.stringify(credentialQuery, undefined, 4))
            const webCredential = await navigator.credentials.get(credentialQuery)
            if (!webCredential) {
                console.error("no webcredential received from wallet!")
            }
            console.log("received from user: " + JSON.stringify(webCredential))
            const redirectURL = await this.validatePresentation(webCredential)
            // redirect user
            console.log(`redirecting user to ${redirectURL}`)
            window.location.replace(redirectURL)
        },
        data() {
            return {
                presentationRequest: null
            }
        },
        methods: {
            async getRequestForPresentation() {
                const handle = this.$route.query.pd
                console.info(`using handle: ${handle}`)
                await this.$http.get(`/presentations/create?pd=${handle}`).then(
                    resp => {
                        this.presentationRequest = resp.data
                    },
                    err => {
                        console.error(`failed to retrieve presentation-definitions: ${err}`)
                        throw err
                    }
                )
            },
            async validatePresentation(presentation) {
                if (!presentation || !presentation.data) {
                    throw new Error("user did not submit a proper web credential")
                }
                const request = {
                    invID: this.presentationRequest.invitation["@id"],
                    vp: presentation.data
                }
                return this.$http.post(`/presentations/handleResponse`, request).then(
                    resp => {
                        const redirectURL = resp.data.redirectURL
                        console.log(`submitted presentationHandle=${presentation} and got redirectURL=${redirectURL}`)
                        return redirectURL
                    },
                    err => {
                        console.error(`failed to validate chapi response: ${err}`)
                        throw err
                    }
                )
            }
        }
    }
</script>
<style scoped>
    .gradient {
        background: linear-gradient(90deg, #000428 20%, #004e92 100%);
    }
</style>
