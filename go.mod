module github.com/miclip/sinesync

go 1.25.0

require (
	github.com/asg017/sqlite-vec-go-bindings v0.1.6
	github.com/aws/aws-sdk-go-v2 v1.32.7
	github.com/aws/aws-sdk-go-v2/config v1.28.7
	github.com/aws/aws-sdk-go-v2/credentials v1.17.48
	github.com/aws/aws-sdk-go-v2/service/s3 v1.71.1
	github.com/google/uuid v1.6.0
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/spf13/cobra v1.10.2
	github.com/yalue/onnxruntime_go v1.25.0
	github.com/zalando/go-keyring v0.2.6
	golang.org/x/crypto v0.47.0
	golang.org/x/term v0.39.0
	golang.org/x/text v0.33.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.7 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.3 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
)

replace github.com/mutecomm/go-sqlcipher/v4 => github.com/miclip/go-sqlcipher/v4 v4.4.3-0.20260209183651-988da792235a
