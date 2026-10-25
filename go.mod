module github.com/sinesync/cli

go 1.26.0

require (
	github.com/asg017/sqlite-vec-go-bindings v0.1.6
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.4
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.3
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/spf13/cobra v1.10.2
	github.com/yalue/onnxruntime_go v1.25.0
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
	golang.org/x/text v0.43.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.23 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

replace github.com/mutecomm/go-sqlcipher/v4 => github.com/sinesync/go-sqlcipher/v4 v4.4.3-0.20260914032728-918acc6b6791
