module github.com/alvarolm/saferbullet

go 1.25.4

require (
	github.com/Diogenesoftoronto/go-gitignore v1.1.0
	github.com/alvarolm/saferbullet/plug-signer v0.0.0-20260116001005-c474caa18d16
	github.com/charlievieth/fastwalk v1.0.14
	github.com/djherbis/times v1.6.0
	github.com/go-chi/chi/v5 v5.2.4
	github.com/go-chi/render v1.0.3
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/gomarkdown/markdown v0.0.0-20250810172220-2e2c11897d1a
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/prometheus/client_golang v1.23.2
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
)

// use local
replace github.com/alvarolm/saferbullet/plug-signer => ./plug-signer

require (
	aead.dev/minisign v0.3.0 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
