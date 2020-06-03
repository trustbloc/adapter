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
    </div>
</template>

<script>
    export default {
        name: 'credentials',
        created: function() {
            const handle = this.getRequestPresentationHandle()
            const request = this.getRequestForPresentation(handle)
            const presentation = this.requestPresentation(request)
            const redirectURL = this.validatePresentation(presentation)
            // redirect user
            console.log(`redirecting user to ${redirectURL}`)
        },
        methods: {
            getRequestPresentationHandle() {
                // TODO extract handle for a presentation request from URL
            },
            getRequestForPresentation(handle) {
                // TODO call backend to exchange this handle for a request for presentation
                const result = {}
                console.log(`exchanged handle=${handle} for a request=${result}`)
                return result
            },
            requestPresentation(request) {
                // TODO submit request for presentation to the user via CHAPI, await and return response
                const response = {}
                console.log(`submitted CHAPI request=${request} and received response=${response}`)
                return response
            },
            validatePresentation(presentation) {
                // TODO submit user presentation to the backend for validation and return redirect URL
                const redirectURL = "http://test.com"
                console.log(`submitted presentation=${presentation} and got redirectURL=${redirectURL}`)
                return redirectURL
            }
        }
    }
</script>
