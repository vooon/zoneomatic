module github.com/vooon/zoneomatic

go 1.25.7

require (
	github.com/alecthomas/kong v1.15.0
	github.com/getkin/kin-openapi v0.135.0
	github.com/go-fuego/fuego v0.19.0
	github.com/miekg/dns v1.1.72
	github.com/otiai10/copy v1.14.1
	github.com/pires/go-proxyproto v0.11.0
	github.com/stretchr/testify v1.11.1
	github.com/vooon/zoneomatic/pkg/dnsfmt v0.0.0-20260404092518-4efbc73326d7
	golang.org/x/crypto v0.49.0
)

replace (
	github.com/vooon/zoneomatic/pkg/dnsfmt => ./pkg/dnsfmt
	github.com/vooon/zoneomatic/pkg/zonefile => ./pkg/zonefile
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/go-openapi/jsonpointer v0.22.5 // indirect
	github.com/go-openapi/swag/jsonname v0.25.5 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/schema v1.4.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mailru/easyjson v0.9.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/oasdiff/yaml v0.0.9 // indirect
	github.com/oasdiff/yaml3 v0.0.9 // indirect
	github.com/otiai10/mint v1.6.3 // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/woodsbury/decimal128 v1.4.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
