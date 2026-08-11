package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwks"
	"github.com/veles-security/voauth/jwksendpoint"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/token"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenrequest"
)

const keyID = "sts-signing-key"

type config struct {
	Issuer        string
	SourceIssuer  string
	SourceJwksURL string
	TokenLifetime time.Duration
}

type server struct {
	config        config
	tokenEndpoint *tokenendpoint.TokenEndpoint
	jwksEndpoint  *jwksendpoint.JwksEndpoint
}

func newServer(configuration config) (*server, error) {
	if configuration.Issuer == "" || configuration.SourceIssuer == "" || configuration.SourceJwksURL == "" || configuration.TokenLifetime <= 0 {
		return nil, errors.New("STS requires issuer, source issuer, source JWKS URL, and a positive token lifetime")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	signer := &sig.Signer{Key: privateKey, Alg: sig.SigAlgRS256, Kid: keyID}

	decoder, err := jwt.NewDecoder()
	if err != nil {
		return nil, fmt.Errorf("create source JWT decoder: %w", err)
	}
	setReader, err := jwks.NewReader()
	if err != nil {
		return nil, fmt.Errorf("create source JWKS reader: %w", err)
	}

	setEndpoint, err := jwksendpoint.New(jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(signer)))
	if err != nil {
		return nil, fmt.Errorf("create STS JWKS endpoint: %w", err)
	}

	s := &server{
		config:       configuration,
		jwksEndpoint: setEndpoint,
	}
	sourceDecoder := &sourceTokenDecoder{
		issuer:     configuration.SourceIssuer,
		jwksURL:    configuration.SourceJwksURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		setReader:  setReader,
		decoder:    decoder,
	}

	s.tokenEndpoint, err = tokenendpoint.New(
		tokenendpoint.WithTokenRequestAuthenticatorOptions(
			tokenrequest.WithAuthenticatorValidatorOptions(
				tokenrequest.WithAllowedGrantTypes(tokenrequest.JwtBearerGrantType),
				tokenrequest.WithClientCredentialsValidatoOptions(
					clientcredentials.WithValidatorAllowedMethods(clientcredentials.PrivateKeyJwtAuthMethod),
				),
			),
			tokenrequest.WithAuthenticatorAuthCallback(tokenrequest.JwtBearerGrantType, s.authenticateAssertion),
		),
		tokenendpoint.WithIssuerOptions(
			jwt.WithSigner(signer),
		),
		tokenendpoint.WithTokenResponseWriterOptions(),
		tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedAccessToken),
		tokenendpoint.WithIssuerOptionsCallback(s.prepareIssuerOptions),
	)
	if err != nil {
		return nil, fmt.Errorf("create token endpoint: %w", err)
	}
	return s, nil
}

func (s *server) authenticateAssertion(_ context.Context, request *tokenrequest.TokenRequest, _ vapi.Principal) (vapi.Principal, error) {
	sourceToken, ok := request.Assertion.(*jwt.Token)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unexpected assertion type %T", request.Assertion))
	}
	subject, ok := sourceToken.Claims["sub"].(string)
	if !ok || subject == "" {
		return nil, vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("source token has no subject"))
	}
	scope, _ := sourceToken.Claims["scope"].(string)
	return sub.NewBasePrincipal(s.config.SourceIssuer, subject, "oauth2:exchanged_subject").
		WithClaims(sourceToken.Claims).
		WithSource("oauth2:token_exchange").
		WithGrantedScopes(strings.Fields(scope)...), nil
}

func (s *server) prepareIssuerOptions(_ context.Context, principal vapi.ScopedPrincipal, request *tokenrequest.TokenRequest) (tokenendpoint.IssuerOptions, error) {
	sourceToken, ok := request.Assertion.(*jwt.Token)
	if !ok {
		return tokenendpoint.IssuerOptions{}, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("unexpected assertion type %T", request.Assertion))
	}
	return tokenendpoint.IssuerOptions{AccessToken: []jwt.IssuerOption{
		jwt.WithIssuer(s.config.Issuer),
		jwt.WithExp(s.config.TokenLifetime),
		jwt.WithClaims(jwt.Cliams{
			"scope": strings.Join(principal.GrantedScopes(), " "),
			"act":   map[string]any{"iss": s.config.SourceIssuer, "sub": sourceToken.Claims["sub"]},
		}),
	}}, nil
}

type sourceTokenDecoder struct {
	issuer     string
	jwksURL    string
	httpClient *http.Client
	setReader  *jwks.Reader
	decoder    *jwt.Decoder
}

func (d *sourceTokenDecoder) Decode(ctx context.Context, payload []byte) (*jwt.Token, error) {
	parts := strings.Split(string(payload), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, errors.New("source token is not a compact JWT"))
	}
	headerPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode source JWT header: %w", err))
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerPayload, &header); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode source JWT header JSON: %w", err))
	}
	if header.Alg == "" || header.Alg == "none" || header.Kid == "" {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("source JWT must identify a signing algorithm and key"))
	}
	algorithm, err := sig.NewSigAlgFromOAuth(header.Alg)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("source JWT algorithm: %w", err))
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.jwksURL, nil)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMisconfigured, fmt.Errorf("create source JWKS request: %w", err))
	}
	response, err := d.httpClient.Do(request)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnavailable, fmt.Errorf("fetch source JWKS: %w", err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, vapi.NewErrorCategory(vapi.ErrUnavailable, fmt.Errorf("fetch source JWKS: HTTP %s", response.Status))
	}
	set, err := d.setReader.ReadArtifact(ctx, *response)
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnavailable, fmt.Errorf("read source JWKS: %w", err))
	}

	var verifier *sig.SignVerifier
	for index := range set.Keys {
		if set.Keys[index].Kid == header.Kid && set.Keys[index].Alg == algorithm {
			verifier = &set.Keys[index].SignVerifier
			break
		}
	}
	if verifier == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("source JWKS has no key %q for algorithm %q", header.Kid, header.Alg))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrMalformed, fmt.Errorf("decode source JWT signature: %w", err))
	}
	if err := verifier.VerifySignature(signature, []byte(parts[0]+"."+parts[1]), algorithm); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("verify source JWT signature: %w", err))
	}

	token, err := d.decoder.Decode(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("decode verified source JWT: %w", err)
	}
	validator, err := jwt.NewValidator(
		jwt.WithValidatorRuntimeOptions(
			jwt.WithValidIssuer(d.issuer),
			jwt.WithValidClock(30*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create source JWT validator: %w", err)
	}
	if err := validator.Validate(ctx, token); err != nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, fmt.Errorf("validate source JWT: %w", err))
	}
	return token, nil
}

func (d *sourceTokenDecoder) DecodeAnyToken(ctx context.Context, payload []byte) (token.AnyToken, error) {
	return d.Decode(ctx, payload)
}
