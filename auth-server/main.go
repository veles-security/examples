package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	address := flag.String("address", ":8082", "HTTP listen address")
	configPath := flag.String("config", "clients.yaml", "path to the clients YAML file")
	flag.Parse()

	configuration, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	application, err := newServer(configuration)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /jwks", application.jwksEndpoint)
	mux.Handle("POST /token", application.tokenEndpoint)

	log.Printf("Auth server listening on %s", *address)
	log.Fatal(http.ListenAndServe(*address, mux))
}
