package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("STS listening on :8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}
