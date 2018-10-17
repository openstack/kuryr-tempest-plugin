package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

func handler(w http.ResponseWriter, r *http.Request) {
	hostname, err := os.Hostname()
	log.Println("Received request")
	if err == nil {
		fmt.Fprintf(w, "%s: HELLO! I AM ALIVE!!!\n", hostname)
	}
}

func send_udp_response(conn *net.UDPConn, addr *net.UDPAddr) {
	hostname, err := os.Hostname()
	if err == nil {
		resp_str := fmt.Sprintf("%s: HELLO! I AM ALIVE!!!\n", hostname)
		_, err := conn.WriteToUDP([]byte(resp_str), addr)
		if err != nil {
			log.Println("Failed to reply to client")
		}
	}
}

func run_udp_server(port int) {

	p := make([]byte, 2048)

	log.Println("Running UDP server")
	ser, _ := net.ListenUDP("udp", &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: port, Zone: ""})
	defer ser.Close()

	for {
		_, remoteaddr, err := ser.ReadFromUDP(p)
		if err != nil {
			log.Println("We got an Error on reading")
			continue
		}
		log.Println("Received UDP request")
		send_udp_response(ser, remoteaddr)
	}
}

func udp_handling(wg sync.WaitGroup) {
	udpPort, udpPortPresent := os.LookupEnv("UDP_PORT")

	var port_num int = 9090
	if udpPortPresent {
		port_num, _ = strconv.Atoi(strings.TrimSpace(udpPort))
	}
	run_udp_server(port_num)
}

func http_handling(wg sync.WaitGroup) {
	defer wg.Done()

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
		log.Println("Running HTTPS server")
		log.Fatal(http.ListenAndServeTLS(port, cert, key, nil))
	} else {
		httpPort, confPresent := os.LookupEnv("HTTP_PORT")
		if confPresent {
			port = ":" + strings.TrimSpace(httpPort)
		} else {
			port = ":8080"
		}
		log.Println("Running HTTP server")
		log.Fatal(http.ListenAndServe(port, nil))
	}
	log.Println("Exit HTTP server...")

}

func main() {

	runtime.GOMAXPROCS(2)
	var wg sync.WaitGroup
	wg.Add(2)

	go http_handling(wg)
	go udp_handling(wg)
	wg.Wait()
}
