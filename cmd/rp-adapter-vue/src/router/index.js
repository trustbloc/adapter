/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Credentials from '@/pages/Credentials'
import NotFound from '@/pages/PageNotFound'

const routes = [
    {
        path: "/ui",
        component: Credentials,
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
        component: Credentials,
        children: [
            {
                path: "*",
                component: NotFound
            }
        ]
    }
];
export default routes;
