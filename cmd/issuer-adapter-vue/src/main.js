/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Vue from 'vue'
import App from './App.vue'
import VueRouter from "vue-router";
import routes from "./router/index";
import "@/assets/css/tailwind.css";
import axios from "axios";
import { library, dom } from '@fortawesome/fontawesome-svg-core';
import { fas } from '@fortawesome/free-solid-svg-icons';
import { fab } from '@fortawesome/free-brands-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import VueMaterial from "vue-material";
import 'vue-material/dist/vue-material.min.css'
import 'vue-material/dist/theme/default.css'
import "vue-material/dist/vue-material.css";

library.add(fas, fab)
dom.watch()

Vue.component('font-awesome-icon', FontAwesomeIcon)

Vue.prototype.$http = axios

Vue.config.productionTip = false

const router = new VueRouter({
    mode: 'history',
    routes, // short for routes: routes
    linkExactActiveClass: "nav-item active"
});

Vue.use(VueRouter);
Vue.use(VueMaterial);

new Vue({
    el: "#app",
    render: h => h(App),
    router
});

