package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("Auth server listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
