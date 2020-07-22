/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Layout from "@/pages/layout/Layout";
import WalletConnect from '@/pages/WalletConnect'
import NotFound from '@/pages/PageNotFound'

const routes = [
    {
        path: "/ui",
        component: Layout,
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
        path: '*',
        name: 'NotFound',
        component: Layout,
        children: [
            {
                path: "*",
                component: NotFound
            }
        ]
    }
];

export default routes;
