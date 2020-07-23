/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Layout from "@/pages/layout/Layout";
import Credentials from '@/pages/Credentials'
import NotFound from '@/pages/PageNotFound'

const routes = [
    {
        path: "/ui",
        component: Layout,
        name: "main",
        redirect: "ui/credentials",
        children: [
            {
                path: "credentials",
                name: "Credentials",
                component: Credentials
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
