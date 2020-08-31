# Issuer Adapter and RP Adapter Integration

### 1. Aries Present Proof Protocol 
The RP uses the consent credential received from Wallet to request actual credentials from Issuer Adapter.

#### presentation-request 
```
{
   "@id":"dad51a7a-6dfa-47bc-97eb-22c5500370fb",
   "@type":"https://didcomm.org/present-proof/2.0/request-presentation",
   "formats":[
      {
         "attach_id":"5ac90bde-7cf3-444c-bea9-f0f704c2af5c",
         "format":"trustbloc/UserConsentVerifiableCredential@0.1.0"
      }
   ],
   "request_presentations~attach":[
      {
         "@id":"5ac90bde-7cf3-444c-bea9-f0f704c2af5c",
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
         },
         "mime-type":"application/ld+json"
      }
   ],
   "~thread":{
      "thid":"dad51a7a-6dfa-47bc-97eb-22c5500370fb"
   }
}
```


#### presentation
```
{
   "@id":"4ac3fd64-4b78-45bd-95a5-58025687ae04",
   "@type":"https://didcomm.org/present-proof/2.0/presentation",
   "presentations~attach":[
      {
         "data":{
            "json":{
               "@context":[
                  "https://www.w3.org/2018/credentials/v1"
               ],
               "proof":{
                  "created":"2020-07-27T18:14:51.3241281Z",
                  "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..8ym4i_pkkBBCD2XVHw52ojUdTTx0m_M8ISDiXnnDg4zHkuc1yTaYKNv5LthTrzI0aCd_SWFsbeuyD1_7Re4PCQ",
                  "proofPurpose":"authentication",
                  "type":"Ed25519Signature2018",
                  "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiDRMWtJGSQpcEWctooI5Tq5WiVc1dTnLIBgmTws0LOyKQ#ZQ2YsQehhnDaVTwV1u1P"
               },
               "type":"VerifiablePresentation",
               "verifiableCredential":[
                  {
                     "@context":[
                        "https://www.w3.org/2018/credentials/v1",
                        "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
                        "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
                     ],
                     "credentialStatus":{
                        "id":"https://issuer-vcs.trustbloc.local/status/1",
                        "type":"CredentialStatusList2017"
                     },
                     "credentialSubject":{
                        "id":"",
                        "stmt":{
                           "accountId":"xxxx-xxxx-xxxx-1234",
                           "billingPeriod":"P30D",
                           "customer":{
                              "@type":"Person",
                              "name":"Jane Doe"
                           },
                           "description":"June 2020 CreditCardStatement",
                           "minimumPaymentDue":{
                              "@type":"PriceSpecification",
                              "price":15,
                              "priceCurrency":"CAD"
                           },
                           "paymentDueDate":"2020-06-30T12:00:00",
                           "paymentStatus":"http://schema.org/PaymentDue",
                           "totalPaymentDue":{
                              "@type":"PriceSpecification",
                              "price":200,
                              "priceCurrency":"CAD"
                           },
                           "url":"http://acmebank.com/invoice.pdf"
                        }
                     },
                     "description":"Credit Card Statement of Mr.John Smith",
                     "id":"http://example.com/4bef0726-3ed2-42e9-8143-53664864423f",
                     "issuanceDate":"2020-07-27T18:14:15.7969826Z",
                     "issuer":{
                        "id":"did:trustbloc:testnet.trustbloc.local:EiD4P85CI_4QyUvw0XvGIP3q4t0O3DBW8aXquGqRTNFUtQ",
                        "name":"trustbloc-ed25519signature2018-ed25519"
                     },
                     "name":"Credit Card Statement",
                     "proof":{
                        "created":"2020-07-27T18:14:17.6008386Z",
                        "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..ahA1uEosXq1XASySyULQcKoUzrUn0o1-3U1cQkNZ3GH0UThv1QDmIBEvsPMwKphTI5gnj2bkxMYBAH74CH0xBg",
                        "proofPurpose":"assertionMethod",
                        "type":"Ed25519Signature2018",
                        "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiD4P85CI_4QyUvw0XvGIP3q4t0O3DBW8aXquGqRTNFUtQ#OCgi6vnHonPMALJbEs2Y"
                     },
                     "type":[
                        "VerifiableCredential",
                        "CreditCardStatement"
                     ]
                  }
               ]
            }
         }
      }
   ],
   "~thread":{
      "thid":"dad51a7a-6dfa-47bc-97eb-22c5500370fb"
   }
}
```
