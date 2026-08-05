package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("Client app listening on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}
