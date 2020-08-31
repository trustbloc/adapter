# Issuer Adapter

### 1. Wallet Connect - CHAPI
The Issuer adapter passes the DIDExchange invitation along with Issuer manifest in the CHAPI request. Behind the scenes, 
the Wallet and Issuer adapter connect through DIDExchange protocol. 

#### Request 
```
{
   "web":{
      "VerifiablePresentation":{
         "query":{
            "type":"DIDConnect"
         },
         "invitation":{
            "serviceEndpoint":"https://issuer-adapter.trustbloc.local",
            "recipientKeys":[
               "DyxPzYzFWYxkYbfWtpaXRUBUVu52LJ3mgXMCSfKZsf3P"
            ],
            "@id":"338ffd4c-3eee-4bc5-921b-894f62327cff",
            "label":"issuer",
            "@type":"https://didcomm.org/didexchange/1.0/invitation"
         },
         "credentials":[
            {
               <manifest vc>
            },
            {
               <governance vc>
            },
            {
               <user vc (if issuer supports assurance data)>
            }
         ]
      }
   }
}
```

#### Response
```
{
   "@context":[
      "https://www.w3.org/2018/credentials/v1"
   ],
   "holder":"did:trustbloc:testnet.trustbloc.local:EiAcoV2d2epezCNRPHViEgaIJ0UeO6pIF6PZgEpnSWVtWw",
   "proof":{
      "created":"2020-07-27T13:48:02.661-04:00",
      "domain":"issuer-adapter.trustbloc.local:10061",
      "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Uj3DxSpuoKNl_4W6zNCFwoEMY__jL8Fqv2JD71jfmdcq-fMYTLsNY0EGVfIERet5n3W_w66Fm7Imao746Ov0Ag",
      "proofPurpose":"authentication",
      "type":"Ed25519Signature2018",
      "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiAcoV2d2epezCNRPHViEgaIJ0UeO6pIF6PZgEpnSWVtWw#Otvzdj4w42AqoUA-dD6n"
   },
   "type":"VerifiablePresentation",
   "verifiableCredential":[
      {
         "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
         ],
         "credentialSubject":{
            "connectionState":"completed",
            "id":"7db9149c-159a-414b-9ced-bc0ecce4e76f",
            "inviteeDID":"did:peer:1zQmagWBWZAuoJPDuE5UbX2mEG2nxmZCpsmNZdkA7WTfWM8p",
            "inviterDID":"did:peer:1zQmUUA4cbM9hyeNiRcUyNXnUMRCfoQzPUbNwQfja1UX81yW",
            "inviterLabel":"issuer",
            "threadID":"338ffd4c-3eee-4bc5-921b-894f62327cff"
         },
         "issuanceDate":"2020-07-27T17:48:01.762Z",
         "issuer":"did:trustbloc:testnet.trustbloc.local:EiAcoV2d2epezCNRPHViEgaIJ0UeO6pIF6PZgEpnSWVtWw",
         "proof":{
            "created":"2020-07-27T13:48:01.934-04:00",
            "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..qfF0j6RbUGxdoFxJUjWcpRLmxmJ_ErGks6JStoKC-z64PBZ0UHBw7-ymYe-i0ZBYVLRmSSedlGseruhkdU9xBw",
            "proofPurpose":"assertionMethod",
            "type":"Ed25519Signature2018",
            "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiAcoV2d2epezCNRPHViEgaIJ0UeO6pIF6PZgEpnSWVtWw#Otvzdj4w42AqoUA-dD6n"
         },
         "type":[
            "VerifiableCredential",
            "DIDConnection"
         ]
      }
   ]
}
```

### 2.1 Aries Issue Credential Protocol 
When RP asks for the credential from the Wallet, the Wallet will initiate issue credential protocol to receive the 
Consent Credential from the Issuer adapter.

#### credential-request 
```
{
   "@id":"a6f7273b-684f-4721-9488-de04f8f9857f",
   "@type":"https://didcomm.org/issue-credential/2.0/request-credential",
   "requests~attach":[
      {
         "data":{
            "json":{
               "rpDIDDoc":{
                  "doc":{
                        <RP DID Document>
                     ],
                     "updated":"2020-07-27T18:14:48.1399025Z"
                  },
                  "id":"did:peer:1zQmWpzw8PAw89myLLBWvkbrS7ygRzPrZXziTSMXaRh5jg7q"
               },
               "userDID":"did:peer:1zQmVmaLuEDmMEf4wcdELyyNdEvh2iLGcf491JDeMCVjVFAa"
            }
         },
         "lastmod_time":"2020-07-27T18:14:48.439Z"
      }
   ],
   "~thread":{
      "thid":"a6f7273b-684f-4721-9488-de04f8f9857f"
   }
}
```

#### issue-credential
```
{
   "@id":"8931899c-9412-4b00-89b8-f5c80b74dddd",
   "@type":"https://didcomm.org/issue-credential/2.0/issue-credential",
   "credentials~attach":[
      {
         "data":{
            "json":{
               "@context":[
                  "https://www.w3.org/2018/credentials/v1",
                  "https://trustbloc.github.io/context/vc/consent-credential-v1.jsonld"
               ],
               "credentialSubject":{
                  "id":"urn:uuid:53d798d6-bc51-463b-b903-7d155b898244",
                  "issuerDIDDoc":{
                     "doc":{
                        <Issuer DID Document>
                     },
                     "id":"did:peer:1zQmabEEg5QvoCL7xQue4miS3e9dvuhj8dngMa1mwkBFkNSQ"
                  },
                  "rpDIDDoc":{
                     "doc":{
                        <RP DID Document>
                     },
                     "id":"did:peer:1zQmWpzw8PAw89myLLBWvkbrS7ygRzPrZXziTSMXaRh5jg7q"
                  },
                  "userDID":"did:peer:1zQmVmaLuEDmMEf4wcdELyyNdEvh2iLGcf491JDeMCVjVFAa"
               },
               "id":"urn:uuid:e6c31dbc-4c7c-419c-ac18-562a0190733f",
               "issuanceDate":"2020-07-27T18:14:48.494041Z",
               "issuer":"urn:uuid:614c5060-4d59-48df-811f-01455a2c28b1",
               "proof":{
                  "created":"2020-07-27T18:14:48.6299911Z",
                  "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..32p9yZBTNdUY8ttSY5tpBZgoIP-5U1BV51HF5JOGdj8Ss-NqbK9tDX9YD-bdAm7I8yksoePfofbULEhmEgDaCA",
                  "proofPurpose":"assertionMethod",
                  "type":"Ed25519Signature2018",
                  "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiDRMWtJGSQpcEWctooI5Tq5WiVc1dTnLIBgmTws0LOyKQ#ZQ2YsQehhnDaVTwV1u1P"
               },
               "type":[
                  "VerifiableCredential",
                  "ConsentCredential"
               ]
            }
         }
      }
   ],
   "~thread":{
      "thid":"a6f7273b-684f-4721-9488-de04f8f9857f"
   }
}
```
