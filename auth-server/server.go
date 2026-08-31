package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/veles-security/vapi"
	"github.com/veles-security/vapi/sub"
	_ "github.com/veles-security/vcrypt/backend/rsa"
	"github.com/veles-security/vcrypt/jwksendpoint"
	"github.com/veles-security/vcrypt/jws"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/keysource/randomsource"
	"github.com/veles-security/vcrypt/keystore"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenendpoint"
	"github.com/veles-security/voauth/tokenrequest"
)

const keySource = "app"

type server struct {
	config        config
	keystore      keystore.Keystore
	jwksEndpoint  *jwksendpoint.JwksEndpoint
	tokenEndpoint *tokenendpoint.TokenEndpoint
}

func newServer(configuration config) (*server, error) {
	s := &server{
		config: configuration,
	}

	// keystore
	keystore, err := keystore.New(keystore.WithSource(randomsource.New(keySource, randomsource.RSA2048, 24*time.Hour)))
	if err != nil {
		return nil, fmt.Errorf("keystore init failed: %w", err)
	}
	s.keystore = keystore

	// signer
	signer, err := jws.New(
		jws.WithSignerKeystore(&keystore),
	)
	if err != nil {
		return nil, fmt.Errorf("signer init failed: %w", err)
	}

	// jwks
	s.jwksEndpoint, err = jwksendpoint.New(
		jwksendpoint.WithKeystore(keystore),
		jwksendpoint.WithKeySelector(key.Select(key.WithSource(keySource))),
	)
	if err != nil {
		return nil, fmt.Errorf("JWKS endpoint init failed: %w", err)
	}

	s.tokenEndpoint, err = tokenendpoint.New(
		tokenendpoint.WithTokenRequestAuthenticatorOptions(
			tokenrequest.WithAuthenticatorValidatorOptions(
				tokenrequest.WithAllowedGrantTypes(tokenrequest.ClientCredentialsGrantType),
				tokenrequest.WithClientCredentialsValidatoOptions(
					clientcredentials.WithValidatorAllowedMethods(clientcredentials.ClientSecretPostAuthMethod),
				),
			),
			tokenrequest.WithAuthenticatorResolverOptions(
				tokenrequest.WithResolverClientResolverOptions(
					clientcredentials.WithResolverRuntimeOptions(
						clientcredentials.WithResolverAuthenticationMethod(clientcredentials.ClientSecretPostAuthMethod, s.authenticateClient),
					),
				),
				tokenrequest.WithResolverRuntimeOptions(
					tokenrequest.WithResolveFunc(s.authenticateSubject),
				),
			),
		),
		tokenendpoint.WithIssuerOptions(
			jwt.WithSigner(signer),
		),
		tokenendpoint.WithTokenResponseWriterOptions(),
		tokenendpoint.WithIssuedTokens(tokenendpoint.IssuedAccessToken),
		tokenendpoint.WithIssuerOptionsCallback(s.prepareIssuerOptions),
	)
	if err != nil {
		return nil, fmt.Errorf("token endpoint init failed: %w", err)
	}

	return s, nil
}

func (s *server) authenticateClient(_ context.Context, credentials *clientcredentials.ClientCredentials) (vapi.Principal, error) {
	for _, client := range s.config.Clients {
		idMatches := subtle.ConstantTimeCompare([]byte(client.ID), []byte(credentials.ClientId)) == 1
		secretMatches := subtle.ConstantTimeCompare([]byte(client.Secret), []byte(credentials.ClientSecret)) == 1
		if idMatches && secretMatches {
			return sub.NewBasePrincipal(s.config.Issuer, client.ID, "oauth2:client").
				WithClaims(client.Claims).
				WithAttributes(map[string]any{"allowed_scopes": slices.Clone(client.Scopes)}), nil
		}
	}
	return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("invalid client credentials"))
}

func (s *server) authenticateSubject(_ context.Context, request *tokenrequest.TokenRequest, client vapi.Principal) (vapi.Principal, error) {
	if client == nil {
		return nil, vapi.NewErrorCategory(vapi.ErrUnauthenticated, errors.New("client credentials grant requires an authenticated client"))
	}
	allowedScopes, ok := client.Attributes()["allowed_scopes"].([]string)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("authenticated client has no allowed scopes"))
	}
	grantedScopes, ok := grantScopes(request.Scope, allowedScopes)
	if !ok {
		return nil, vapi.NewErrorCategory(vapi.ErrPolicyRejected, errors.New("requested scope is not allowed"))
	}

	return sub.NewBasePrincipal(client.Issuer(), client.Subject(), client.Kind()).
		WithClaims(client.Claims()).
		WithAttributes(client.Attributes()).
		WithActor(client.Actor()).
		WithSource("oauth2:client_credentials").
		WithGrantedScopes(grantedScopes...), nil
}

func (s *server) prepareIssuerOptions(_ context.Context, principal vapi.ScopedPrincipal) (tokenendpoint.IssuerOptions, error) {
	return tokenendpoint.IssuerOptions{
		AccessToken: []jwt.IssuerOption{
			jwt.WithIssuer(s.config.Issuer),
			jwt.WithExp(time.Duration(s.config.TokenLifetimeSeconds) * time.Second),
			jwt.WithClaims(jwt.Cliams{"scope": strings.Join(principal.GrantedScopes(), " ")}),
		},
	}, nil
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
