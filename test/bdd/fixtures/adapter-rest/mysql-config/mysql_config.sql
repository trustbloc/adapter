/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

/*
RP Adapter
*/
CREATE USER 'rpadapter'@'%' IDENTIFIED BY 'rpadapter-secret-pw';
GRANT ALL PRIVILEGES ON `rpadapter\_%` . * TO 'rpadapter'@'%';

/*
RP Adapter's Hydra instance
*/
CREATE USER 'rpadapterhydra'@'%' IDENTIFIED BY 'rpadapterhydra-secret-pw';
CREATE DATABASE rpadapterhydra;
GRANT ALL PRIVILEGES ON rpadapterhydra.* TO 'rpadapterhydra'@'%';

/*
Issuer Adapter
*/
CREATE USER 'issueradapter'@'%' IDENTIFIED BY 'issueradapter-secret-pw';
GRANT ALL PRIVILEGES ON `issueradapter\_%` . * TO 'issueradapter'@'%';

