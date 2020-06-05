/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

<template>
    <div class="wrapper">
        <div class="contents">
            <transition name="fade" mode="out-in">
                <router-view></router-view>
            </transition>
            <layout-footer class="footer" v-if="!$route.meta.hideFooter"></layout-footer>
        </div>
    </div>
</template>

<script>
    import Footer from "./Footer.vue";

    export default {
        components: {
            LayoutFooter: Footer,
        }
    };
</script>

<style scoped>
    div {
        text-align: center;
    }
</style>
