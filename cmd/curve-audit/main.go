package main

import (
	"fmt"
	"github.com/syncsynchalt/curve-audit/tls"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s host port\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	port := os.Args[2]
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		panic(err)
	}

	result, err := tls.CheckCurve(conn, host)
	if err != nil {
		panic(err)
	}

    fmt.Printf("Result: %s\n", result)
}
