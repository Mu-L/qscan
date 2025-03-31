module Qscan

go 1.23

toolchain go1.23.2

require (
	github.com/atotto/clipboard v0.1.4
	//database
	github.com/denisenkom/go-mssqldb v0.10.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/huin/asn1ber v0.0.0-20120622192748-af09f62e6358
	github.com/icodeface/tls v0.0.0-20190904083142-17aec93c60e5
	github.com/jlaffaye/ftp v0.0.0-20220630165035-11536801d1ff
	github.com/lcvvvv/appfinger v0.1.1

	//gonmap
	github.com/lcvvvv/gonmap v1.3.4
	github.com/lcvvvv/pool v0.0.0-00010101000000-000000000000
	github.com/lcvvvv/simplehttp v0.1.1
	github.com/lcvvvv/stdio v0.1.2
	github.com/lib/pq v1.10.2

	//grdp
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40
	github.com/miekg/dns v1.1.50
	github.com/sijms/go-ora/v2 v2.2.15

	//protocol
	github.com/stacktitan/smb v0.0.0-20190531122847-da9a425dceb8
	go.mongodb.org/mongo-driver v1.7.1
	golang.org/x/crypto v0.33.0

	//chinese
	golang.org/x/text v0.22.0
)

require (
	github.com/IBM/sarama v1.45.1
	github.com/go-ldap/ldap/v3 v3.4.10
	github.com/gocql/gocql v1.7.0
	github.com/google/cel-go v0.20.1
	github.com/gookit/color v1.5.4
	github.com/gosnmp/gosnmp v1.39.0
	github.com/mitchellh/go-vnc v0.0.0-20150629162542-723ed9867aed
	github.com/neo4j/neo4j-go-driver/v4 v4.4.8
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/satori/go.uuid v1.2.0
	golang.org/x/net v0.35.0
	google.golang.org/genproto/googleapis/api v0.0.0-20240318140521-94a12d6c2237
	google.golang.org/protobuf v1.33.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/PuerkitoBio/goquery v1.8.0 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/eapache/go-resiliency v1.7.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.7 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hailocab/go-hostpool v0.0.0-20160125115350-e80d13ce29ed // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/twmb/murmur3 v1.1.6 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.0.2 // indirect
	github.com/xdg-go/stringprep v1.0.2 // indirect
	github.com/xo/terminfo v0.0.0-20210125001918-ca9a967f8778 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	golang.org/x/exp v0.0.0-20230515195305-f3d0a9c9a5cc // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/tools v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240314234333-6e1732d8331c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
)

replace github.com/lcvvvv/pool => ./lib/pool

//replace github.com/lcvvvv/gonmap => ../go-github/gonmap
