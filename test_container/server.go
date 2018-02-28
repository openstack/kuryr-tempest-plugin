package main

import (
        "fmt"
        "log"
        "net/http"
        "os"
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
    log.Fatal(http.ListenAndServe(":8080", nil))
}
