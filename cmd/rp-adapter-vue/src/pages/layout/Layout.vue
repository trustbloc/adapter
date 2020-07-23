/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

<template>
  <div class="contents">
    <nav id="header" class="fixed w-full z-30 top-0 text-white">

      <div class="w-full container mx-auto flex flex-wrap items-center justify-between mt-0 py-2">
        <div class="pl-4 flex items-center">
          <a class="toggleColour text-white no-underline hover:no-underline font-bold text-2xl lg:text-4xl"
             href="/ui">
            TrustBloc Relying Party Adapter
          </a>
        </div>

        <div class="block lg:hidden pr-4">
          <button id="nav-toggle" class="flex items-center p-1 text-orange-800 hover:text-gray-900">
            <svg class="fill-current h-6 w-6" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
              <title>
                Menu</title>
              <path d="M0 3h20v2H0V3zm0 6h20v2H0V9zm0 6h20v2H0v-2z"/>
            </svg>
          </button>
        </div>

        <div class="w-full flex-grow lg:flex lg:items-center lg:w-auto hidden lg:block mt-2 lg:mt-0 bg-white lg:bg-transparent text-black p-4 lg:p-0 z-20"
             id="nav-content">
          <ul class="list-reset lg:flex justify-end flex-1 items-center">
            <li class="mr-3">
              <a class="inline-block text-black no-underline hover:text-green hover:text-underline py-2 px-4"
                 href="https://github.com/trustbloc/edge-adapter">Github</a>
            </li>
          </ul>
        </div>
      </div>

      <hr class="border-b border-gray-100 opacity-25 my-0 py-0 white"/>

    </nav>

    <svg id="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg"
         xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1428.11 145.64">
      <defs>
        <linearGradient id="Sky" x1="7.63" y1="202.65" x2="1435.13" y2="202.65"
                        gradientTransform="matrix(-1, -0.01, 0.01, -0.97, 1422.21, 487.83)"
                        gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="#cce0f4"/>
          <stop offset="0.06" stop-color="#c3dcf2"/>
          <stop offset="0.17" stop-color="#a9d2ee"/>
          <stop offset="0.31" stop-color="#80c2e7"/>
          <stop offset="0.46" stop-color="#47acde"/>
          <stop offset="0.57" stop-color="#1e9cd7"/>
          <stop offset="0.87" stop-color="#0075be"/>
          <stop offset="0.99" stop-color="#005b97"/>
        </linearGradient>
      </defs>
      <path class="cls-1" style="fill: url(#Sky)"
            d="M1416.4,286.51a12.74,12.74,0,0,1-12.81,12.39c-161.08,50.27-387.9,91.63-642.53,39.86A1186,1186,0,0,1,645.44,309.1a1685.83,1685.83,0,0,0-184.8-26.2,1703.48,1703.48,0,0,0-444,20.53l-15-.14a12.75,12.75,0,0,1-12.88-12.63l.49-55a12.76,12.76,0,0,1,12.93-12.4L1403.85,217a12.76,12.76,0,0,1,13.06,12.63Z"
            transform="translate(11.2 -216.98)"/>
    </svg>

    <div class="align-middle">
      <transition name="fade" mode="out-in">
        <router-view></router-view>
      </transition>

      <br/>
      <svg id="Layer_1" class="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg"
           xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1428.22 144.92">
        <defs>
          <linearGradient id="Sky" x1="3.63" y1="202.68" x2="1431.13" y2="202.68"
                          gradientTransform="matrix(1, 0.01, -0.01, 0.97, -8.59, 81.53)"
                          gradientUnits="userSpaceOnUse">
            <stop offset="0" stop-color="#cce0f4"/>
            <stop offset="0.06" stop-color="#c3dcf2"/>
            <stop offset="0.17" stop-color="#a9d2ee"/>
            <stop offset="0.31" stop-color="#80c2e7"/>
            <stop offset="0.46" stop-color="#47acde"/>
            <stop offset="0.57" stop-color="#1e9cd7"/>
            <stop offset="0.87" stop-color="#0075be"/>
            <stop offset="0.99" stop-color="#005b97"/>
          </linearGradient>
        </defs>
        <title>Untitled-3</title>
        <path class="cls-1" style="opacity: 0.56;
                        fill: url(#Sky);"
              d="M-7.13,282.85A12.75,12.75,0,0,1,5.7,270.48c161.17-50,388.06-90.94,642.6-38.71a1187.23,1187.23,0,0,1,115.57,29.86,1686.07,1686.07,0,0,0,184.75,26.53,1703.57,1703.57,0,0,0,444-19.73l15,.16a12.77,12.77,0,0,1,12.86,12.65l-.6,55a12.75,12.75,0,0,1-12.95,12.38L5.3,352.4a12.77,12.77,0,0,1-13-12.65Z"
              transform="translate(7.75 -207.49)"/>
      </svg>
      <br/>
      <br/>
      <layout-footer v-if="!$route.meta.hideFooter"></layout-footer>
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

  .Layer_1 {
    position: fixed;
    bottom: 0;
  }
</style>