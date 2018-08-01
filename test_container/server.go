package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	hostname, err := os.Hostname()
	log.Println("Received request")
	if err == nil {
		fmt.Fprintf(w, "%s: HELLO! I AM ALIVE!!!\n", hostname)
	}
}

func main() {
	http.HandleFunc("/", handler)

	httpsPort, httpsPortPresent := os.LookupEnv("HTTPS_PORT")

	var port string
	if httpsPortPresent {
		port = ":" + strings.TrimSpace(httpsPort)

		cert, certPresent := os.LookupEnv("HTTPS_CERT_PATH")
		key, keyPresent := os.LookupEnv("HTTPS_KEY_PATH")

		if !certPresent || !keyPresent {
			log.Fatal("HTTPS_PORT configured but missing HTTPS_CERT_PATH and/or HTTPS_KEY_PATH")
		}

		log.Fatal(http.ListenAndServeTLS(port, cert, key, nil))
	} else {
		httpPort, confPresent := os.LookupEnv("HTTP_PORT")
		if confPresent {
			port = ":" + strings.TrimSpace(httpPort)
		} else {
			port = ":8080"
		}

		log.Fatal(http.ListenAndServe(port, nil))
	}
}
