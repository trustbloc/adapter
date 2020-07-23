<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div>
        <div class="pt-10">
            <br/>The <strong>Relying Party Adapter</strong> requests credentials and creates a <strong>DIDComm connection</strong> with
            the <strong>User's Wallet </strong>on behalf of the Relying Party.
            <br/>The Wallet may provide the credentials directly as a Holder, or it may provide an <strong>AuthorizationCredential</strong>
            the Adapter can use to fetch the user's credentials at the
            <br/>location specified within.
            <br/>
            <br/>
            <br/>
            <br/>
            <br/>
            <br/>
        </div>
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
