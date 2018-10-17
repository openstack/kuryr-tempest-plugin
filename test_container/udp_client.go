package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

// udp_client.go syntax : udp_client <server_IP> <server_port>

func main() {

	server_ip_port := os.Args[1] + ":" + os.Args[2]

	p := make([]byte, 2048)
	conn, err := net.Dial("udp", server_ip_port)
	if err != nil {
		fmt.Printf("Some error %v", err)
		return
	}
	fmt.Fprintf(conn, "Hi UDP Server, How are you?")
	_, err = bufio.NewReader(conn).Read(p)
	if err == nil {
		fmt.Printf("%s\n", p)
	} else {
		fmt.Printf("Some error %v\n", err)
	}
	conn.Close()
}
