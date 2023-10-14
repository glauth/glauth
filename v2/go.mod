module github.com/glauth/glauth/v2

go 1.19

// Do not mistake /vendored for /vendor!
replace github.com/hydronica/toml => ./vendored/toml

require (
	github.com/GeertJohan/yubigo v0.0.0-20190917122436-175bc097e60e
	github.com/arl/statsviz v0.6.0
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/fsnotify/fsnotify v1.6.0
	github.com/hydronica/toml v0.5.0
	github.com/jinzhu/copier v0.4.0
	github.com/nmcclain/ldap v0.0.0-20210720162743-7f8d1e44eeba
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.17.0
	github.com/rs/zerolog v1.31.0
	github.com/smartystreets/goconvey v1.6.4
	github.com/yaegashi/msgraph.go v0.1.4
	golang.org/x/crypto v0.14.0
	gopkg.in/amz.v3 v3.0.0-20201001071545-24fc1eceb27b
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20181017120253-0766667cb4d1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rickb777/date v1.20.5 // indirect
	github.com/rickb777/plural v1.4.1 // indirect
	github.com/smartystreets/assertions v0.0.0-20180927180507-b2de0cb4f26d // indirect
	golang.org/x/sys v0.13.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
