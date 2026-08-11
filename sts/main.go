package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	address := flag.String("address", ":8083", "HTTP listen address")
	issuer := flag.String("issuer", "http://localhost:8083", "issuer for exchanged tokens")
	sourceIssuer := flag.String("source-issuer", "http://localhost:8082", "trusted auth-server issuer")
	sourceJwks := flag.String("source-jwks", "http://localhost:8082/jwks", "trusted auth-server JWKS URL")
	tokenLifetime := flag.Duration("token-lifetime", 15*time.Minute, "lifetime of exchanged access tokens")
	flag.Parse()

	application, err := newServer(config{
		Issuer:        *issuer,
		SourceIssuer:  *sourceIssuer,
		SourceJwksURL: *sourceJwks,
		TokenLifetime: *tokenLifetime,
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /jwks", application.jwksEndpoint)
	mux.Handle("POST /token", application.tokenEndpoint)

	log.Printf("STS listening on %s", *address)
	log.Fatal(http.ListenAndServe(*address, mux))
}
