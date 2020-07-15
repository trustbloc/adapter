<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div class="hello">
        <h1>Please provide credentials</h1>
        <!--
            TODO pretty UI
        -->

        <textarea v-model="presentationRequestView"></textarea>
    </div>
</template>

<script>
    export default {
        name: 'credentials',
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
                presentationRequest: null,
                presentationRequestView: null
            }
        },
        methods: {
            async getRequestForPresentation() {
                const handle = this.$route.query.pd
                console.info(`using handle: ${handle}`)
                await this.$http.get(`/presentations/create?pd=${handle}`).then(
                    resp => {
                        this.presentationRequest = resp.data
                        this.presentationRequestView = JSON.stringify(resp.data, null, 2)
                        console.log(`exchanged handle=${handle} for a request=${this.presentationRequestView}`)
                    },
                    err => {
                        console.error(`failed to retrieve presentation-definitions: ${err}`)
                        throw err
                    }
                )
            },
            async validatePresentation(presentation) {
                const request = {
                    invID: this.presentationRequest.invitation["@id"],
                    vp: presentation
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
