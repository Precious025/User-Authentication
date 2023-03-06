package main

import (
	"log"
	"net/http"
)

func main() {

	http.HandleFunc("/login", Login)
	http.HandleFunc("/home", Home)
	log.Println("Listening on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
