package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/vapi/sub"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwks"
	"github.com/veles-security/voauth/jwksendpoint"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

const keyID = "auth-server-signing-key"

type server struct {
	config        config
	signer        *sig.Signer
	jwksEndpoint  *jwksendpoint.JwksEndpoint
	tokenEndpoint *tokenendpoint.TokenEndpoint
}

func newServer(configuration config) (*server, error) {
	s := &server{
		config: configuration,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	s.signer = &sig.Signer{Key: privateKey, Alg: sig.SigAlgRS256, Kid: keyID}

	jwksEndpoint, err := jwksendpoint.New(
		jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(s.signer)),
	)
	if err != nil {
		return nil, fmt.Errorf("create JWKS endpoint: %w", err)
	}
	s.jwksEndpoint = jwksEndpoint

	tokenEndpoint, err := tokenendpoint.New(
		tokenendpoint.WithTokenRequestValidatorOption(
			tokenrequest.WithAllowedGrantTypes(tokenrequest.ClientCredentialsGrantType),
		),
		tokenendpoint.WithClientCredentialsValidatorOption(
			clientcredentials.WithAllowedMethods(clientcredentials.ClientSecretPostAuthMethod),
		),
		tokenendpoint.WithJWTIssuerOption(jwt.WithSigner(s.signer)),
		tokenendpoint.WithIssuerOptionsCallback(s.issuerOptions),
		tokenendpoint.WithTokenResponseCallback(s.tokenResponse),
	)
	if err != nil {
		return nil, fmt.Errorf("create token endpoint: %w", err)
	}
	s.tokenEndpoint = tokenEndpoint

	return s, nil
}

func (s *server) issuerOptions(ctx context.Context, request *tokenrequest.TokenRequest) ([]jwt.IssuerOption, error) {
	client, err := s.authenticate(ctx, &request.ClientCredentials)
	if err != nil {
		return nil, err
	}
	allowedScopes, ok := client.Attributes()["allowedScopes"].([]string)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("client has no allowed scopes"))
	}

	grantedScopes, ok := grantScopes(request.Scope, allowedScopes)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("requested scope is not allowed"))
	}

	lifetime := time.Duration(s.config.TokenLifetimeSeconds) * time.Second
	return []jwt.IssuerOption{
		jwt.WithIssuer(s.config.Issuer),
		jwt.WithSubject(client.Subject()),
		jwt.WithExp(lifetime),
		jwt.WithClaims(jwt.Cliams(client.Claims())),
		jwt.WithClaims(jwt.Cliams{"scope": strings.Join(grantedScopes, " ")}),
	}, nil
}

func (s *server) tokenResponse(_ context.Context, _ *tokenrequest.TokenRequest, accessToken *jwt.Token) (*tokenresponse.TokenResponse, error) {
	grantedScopes, ok := accessToken.Claims["scope"].(string)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrInternal, errors.New("issued access token has no scope claim"))
	}
	return &tokenresponse.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   time.Duration(s.config.TokenLifetimeSeconds) * time.Second,
		Scope:       grantedScopes,
	}, nil
}

func (s *server) authenticate(_ context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
	for _, client := range s.config.Clients {
		idMatches := subtle.ConstantTimeCompare([]byte(client.ID), []byte(credentials.ClientId)) == 1
		secretMatches := subtle.ConstantTimeCompare([]byte(client.Secret), []byte(credentials.ClientSecret)) == 1
		if idMatches && secretMatches {
			return sub.NewBasePrincipal(
				s.config.Issuer,
				client.ID,
				"",
			).WithClaims(client.Claims).WithAttributes(map[string]any{
				"allowedScopes": client.Scopes,
			}), nil
		}
	}
	return nil, vapi.ErrUnauthenticated
}

func grantScopes(requested string, allowed []string) ([]string, bool) {
	if requested == "" {
		return slices.Clone(allowed), true
	}
	requestedScopes := strings.Fields(requested)
	for _, scope := range requestedScopes {
		if !slices.Contains(allowed, scope) {
			return nil, false
		}
	}
	return requestedScopes, true
}
