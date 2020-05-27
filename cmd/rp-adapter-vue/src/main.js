/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Vue from 'vue'
import App from './App.vue'

import * as polyfill from "credential-handler-polyfill";
import * as webCredentialHandler from "web-credential-handler";
Vue.prototype.$polyfill = polyfill
Vue.prototype.$webCredentialHandler = webCredentialHandler

Vue.config.productionTip = false

new Vue({
  render: h => h(App),
}).$mount('#app')
