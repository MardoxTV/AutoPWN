package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/autopwn/scanner/internal/api"
)

func main() {
	port := flag.String("port", "8001", "HTTP port to listen on")
	flag.Parse()

	mux := api.NewServer(*port)
	addr := "127.0.0.1:" + *port
	log.Printf("AutoPwn scanner service listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
