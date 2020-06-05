/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
<template>
    <div class="col-full">
        <h1>Not Found</h1>
        <p>Ooops, we couldn't find what you are looking for. Why don't you
            <router-link :to="{name: 'main'}">
                go home instead?
            </router-link>
        </p>
    </div>
</template>

<script>
    export default {}
</script>

<style scoped>
    h1 {
        font-size: 50px;
    }

    p {
        font-size: 30px;
        font-weight: 100;
    }

    div {
        text-align: center;
    }
</style>
