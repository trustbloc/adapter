// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter

go 1.17

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.8-0.20220209203615-cbec86033851
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.4-0.20211219215001-23cd75276fdc
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220106195936-a9d6794663ed
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220106195936-a9d6794663ed
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	gopkg.in/square/go-jose.v2 v2.5.1
)

require (
	github.com/PaesslerAG/gval v1.1.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/VictoriaMetrics/fastcache v1.5.7 // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833 // indirect
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce // indirect
	github.com/cenkalti/backoff/v4 v4.1.2 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/evanphx/json-patch v4.1.0+incompatible // indirect
	github.com/fxamacker/cbor/v2 v2.3.0 // indirect
	github.com/go-openapi/analysis v0.19.5 // indirect
	github.com/go-openapi/errors v0.19.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.3 // indirect
	github.com/go-openapi/jsonreference v0.19.3 // indirect
	github.com/go-openapi/loads v0.19.4 // indirect
	github.com/go-openapi/runtime v0.19.15 // indirect
	github.com/go-openapi/spec v0.19.3 // indirect
	github.com/go-openapi/strfmt v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.9 // indirect
	github.com/go-openapi/validate v0.19.8 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.2-0.20210512142713-bed466244fa6 // indirect
	github.com/google/tink/go v1.6.1-0.20210519071714-58be99b3c4d0 // indirect
	github.com/google/trillian v1.3.14-0.20210520152752-ceda464a95a3 // indirect
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20211217171603-637696af6620 // indirect
	github.com/hyperledger/aries-framework-go/component/storage/edv v0.0.0-20210820175050-dcc7a225178d // indirect
	github.com/ipfs/go-cid v0.0.7 // indirect
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a // indirect
	github.com/kawamuray/jsonpath v0.0.0-20201211160320-7483bafabd7e // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/mailru/easyjson v0.7.0 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/minio/sha256-simd v0.1.1 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.0.3 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.0.3 // indirect
	github.com/multiformats/go-multihash v0.0.14 // indirect
	github.com/multiformats/go-varint v0.0.6 // indirect
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/rs/cors v1.7.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/tidwall/gjson v1.6.7 // indirect
	github.com/tidwall/match v1.0.3 // indirect
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/tidwall/sjson v1.1.4 // indirect
	github.com/trustbloc/orb v0.1.4-0.20211201141158-15a02b430f04 // indirect
	github.com/trustbloc/sidetree-core-go v0.7.1-0.20211124193658-d5f6ccf1e554 // indirect
	github.com/trustbloc/vct v0.1.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	go.mongodb.org/mongo-driver v1.7.4 // indirect
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c // indirect
	google.golang.org/grpc v1.39.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
