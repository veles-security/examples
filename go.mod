module github.com/veles-security/examples

go 1.26.7

require (
	github.com/veles-security/vapi v1.11.0
	github.com/veles-security/voauth v1.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/veles-security/vcrypt v1.2.0 // indirect

replace github.com/veles-security/voauth => ../voauth

replace github.com/veles-security/vapi => ../vapi
