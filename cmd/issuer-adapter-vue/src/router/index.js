/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Landing from "@/pages/views/Landing";
import WalletConnect from '@/pages/WalletConnect'
import NotFound from '@/pages/PageNotFound'
import GeneralError from '@/pages/GeneralError'

const routes = [
    {
        path: "/ui",
        component: WalletConnect,
        name: "main",
        redirect: "ui/walletConnect",
        children: [
            {
                path: "walletConnect",
                name: "WalletConnect",
                component: WalletConnect
            }
        ]
    },
    {
        path: "/ui/error",
        component: GeneralError,
    },
    {
        path: '*',
        name: 'NotFound',
        component: Landing,
        children: [
            {
                path: "*",
                component: NotFound
            }
        ]
    }
];

export default routes;
