module github.com/glauth/glauth/v2

go 1.19

// Do not mistake /vendored for /vendor!
replace github.com/hydronica/toml => ./vendored/toml

require (
	github.com/GeertJohan/yubigo v0.0.0-20190917122436-175bc097e60e
	github.com/arl/statsviz v0.4.0
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/fsnotify/fsnotify v1.4.9
	github.com/hydronica/toml v0.4.2
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/nmcclain/ldap v0.0.0-20210720162743-7f8d1e44eeba
	github.com/pquerna/otp v1.3.0
	github.com/prometheus/client_golang v1.13.0
	github.com/rs/zerolog v1.28.0
	github.com/smartystreets/goconvey v1.6.4
	github.com/yaegashi/msgraph.go v0.1.1-0.20200221123608-2d438cf2a7cc
	golang.org/x/crypto v0.1.0
	gopkg.in/amz.v3 v3.0.0-20201001071545-24fc1eceb27b
)

require (
	github.com/BurntSushi/go-sumtype v0.0.0-20221020234012-480526a59796 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20181017120253-0766667cb4d1 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/smartystreets/assertions v0.0.0-20180927180507-b2de0cb4f26d // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
