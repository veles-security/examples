package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/veles-security/vapi/sig"
	"github.com/veles-security/voauth/jwks"
	"github.com/veles-security/voauth/jwksendpoint"
	"github.com/veles-security/voauth/jwt"
	"github.com/veles-security/voauth/tokenrequest"
)

func TestServer_ExchangeToken(t *testing.T) {
	sourceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate source key: %v", err)
	}
	sourceSigner := &sig.Signer{Key: sourceKey, Alg: sig.SigAlgRS256, Kid: "auth-server-key"}
	sourceJwks, err := jwksendpoint.New(jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(sourceSigner)))
	if err != nil {
		t.Fatalf("create source JWKS endpoint: %v", err)
	}
	sourceServer := httptest.NewServer(sourceJwks)
	defer sourceServer.Close()

	sourceIssuer, err := jwt.NewIssuer(jwt.WithSigner(sourceSigner))
	if err != nil {
		t.Fatalf("create source issuer: %v", err)
	}
	sourceToken, err := sourceIssuer.Issue(
		context.Background(),
		jwt.WithIssuer("https://auth.example"),
		jwt.WithSubject("client-1"),
		jwt.WithExp(time.Hour),
		jwt.WithClaims(jwt.Cliams{"scope": "messages:read", "tenant_id": "tenant-1"}),
	)
	if err != nil {
		t.Fatalf("issue source token: %v", err)
	}
	encoder, err := jwt.NewEncoder()
	if err != nil {
		t.Fatalf("create source encoder: %v", err)
	}
	encodedSource, err := encoder.Encode(context.Background(), sourceToken)
	if err != nil {
		t.Fatalf("encode source token: %v", err)
	}

	sts, err := newServer(config{
		Issuer:        "https://sts.example",
		SourceIssuer:  "https://auth.example",
		SourceJwksURL: sourceServer.URL,
		TokenLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("newServer() failed: %v", err)
	}
	form := url.Values{
		"grant_type": {tokenrequest.JwtBearerGrantType},
		"assertion":  {string(encodedSource)},
	}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	sts.tokenEndpoint.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ServeHTTP() status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}

	var representation struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &representation); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if representation.AccessToken == "" || representation.AccessToken == string(encodedSource) {
		t.Fatalf("access_token = %q, want a newly issued token", representation.AccessToken)
	}
	if representation.TokenType != "Bearer" || representation.Scope != "messages:read" {
		t.Errorf("token response = %#v, want STS access-token metadata", representation)
	}

	decoder, err := jwt.NewDecoder()
	if err != nil {
		t.Fatalf("create exchanged token decoder: %v", err)
	}
	exchanged, err := decoder.Decode(context.Background(), []byte(representation.AccessToken))
	if err != nil {
		t.Fatalf("decode exchanged token: %v", err)
	}
	if exchanged.Claims["iss"] != "https://sts.example" || exchanged.Claims["sub"] != "client-1" || exchanged.Claims["scope"] != "messages:read" || exchanged.Claims["tenant_id"] != "tenant-1" {
		t.Errorf("exchanged claims = %#v", exchanged.Claims)
	}
}

func TestServer_RejectsTamperedSourceToken(t *testing.T) {
	sourceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate source key: %v", err)
	}
	sourceSigner := &sig.Signer{Key: sourceKey, Alg: sig.SigAlgRS256, Kid: "auth-server-key"}
	sourceJwks, err := jwksendpoint.New(jwksendpoint.WithJwksOption(jwks.WithKeyFromSigner(sourceSigner)))
	if err != nil {
		t.Fatalf("create source JWKS endpoint: %v", err)
	}
	sourceServer := httptest.NewServer(sourceJwks)
	defer sourceServer.Close()
	sts, err := newServer(config{Issuer: "https://sts.example", SourceIssuer: "https://auth.example", SourceJwksURL: sourceServer.URL, TokenLifetime: time.Minute})
	if err != nil {
		t.Fatalf("newServer() failed: %v", err)
	}

	form := url.Values{
		"grant_type": {tokenrequest.JwtBearerGrantType},
		"assertion":  {"eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGgtc2VydmVyLWtleSJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZSIsInN1YiI6ImNsaWVudC0xIn0.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	sts.tokenEndpoint.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("ServeHTTP() = status %d body %q, want invalid_client", response.Code, response.Body.String())
	}
}
