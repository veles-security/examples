package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/jwks"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
	"github.com/veles-security/voauth/tokenresponse"
)

const keyID = "auth-server-signing-key"

type server struct {
	config         config
	requestReader  *tokenrequest.Reader
	issuer         *jwt.Issuer
	jwks           *jwks.Jwks
	jwksWriter     *jwks.Writer
	responseWriter *tokenresponse.Writer
}

func newServer(configuration config) (*server, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	requestReader, err := tokenrequest.NewReader()
	if err != nil {
		return nil, fmt.Errorf("create token request reader: %w", err)
	}
	jwksWriter, err := jwks.NewWriter()
	if err != nil {
		return nil, fmt.Errorf("create JWKS writer: %w", err)
	}
	responseWriter, err := tokenresponse.NewWriter()
	if err != nil {
		return nil, fmt.Errorf("create token response writer: %w", err)
	}

	signer := &sig.Signer{Key: privateKey, Alg: sig.SigAlgRS256, Kid: keyID}

	return &server{
		config:         configuration,
		requestReader:  requestReader,
		issuer:         jwt.NewIssuer(signer, jwt.WithIssuer(configuration.Issuer)),
		jwks:           jwks.NewJwks(jwks.WithKeyFromSigner(signer)),
		jwksWriter:     jwksWriter,
		responseWriter: responseWriter,
	}, nil
}

func (s *server) handleJWKS(response http.ResponseWriter, request *http.Request) {
	if err := s.jwksWriter.WriteArtifact(request.Context(), response, s.jwks); err != nil {
		log.Printf("write JWKS: %v", err)
		http.Error(response, "internal server error", http.StatusInternalServerError)
	}
}

func (s *server) handleToken(response http.ResponseWriter, request *http.Request) {
	tokenRequest, err := s.requestReader.ReadArtifact(request.Context(), request)
	if err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if tokenRequest.GrantType != tokenrequest.ClientCredentialsGrantType {
		writeOAuthError(response, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	credentials := tokenRequest.ClientCredentials
	_, _, usedBasicAuth := request.BasicAuth()
	if usedBasicAuth || credentials.ClientSecret == "" {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_client")
		return
	}

	client, authenticated := s.authenticate(credentials.ClientId, credentials.ClientSecret)
	if !authenticated {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_client")
		return
	}

	grantedScopes, ok := grantScopes(tokenRequest.Scope, client.Scopes)
	if !ok {
		writeOAuthError(response, http.StatusBadRequest, "invalid_scope")
		return
	}

	lifetime := time.Duration(s.config.TokenLifetimeSeconds) * time.Second
	accessToken, err := s.issuer.Issue(
		request.Context(),
		jwt.WithSubject(client.ID),
		jwt.WithExp(lifetime),
		jwt.WithClaims(jwt.Cliams(client.Claims)),
	)
	if err != nil {
		log.Printf("issue access token: %v", err)
		writeOAuthError(response, http.StatusInternalServerError, "server_error")
		return
	}

	err = s.responseWriter.WriteArtifact(request.Context(), response, &tokenresponse.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   lifetime,
		Scope:       strings.Join(grantedScopes, " "),
	})
	if err != nil {
		log.Printf("write token response: %v", err)
	}
}

func (s *server) authenticate(id, secret string) (clientConfig, bool) {
	for _, client := range s.config.Clients {
		idMatches := subtle.ConstantTimeCompare([]byte(client.ID), []byte(id)) == 1
		secretMatches := subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) == 1
		if idMatches && secretMatches {
			return client, true
		}
	}
	return clientConfig{}, false
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

func writeOAuthError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json;charset=UTF-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(map[string]string{"error": code}); err != nil {
		log.Printf("write OAuth error: %v", err)
	}
}
