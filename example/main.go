package main

import (
	"context"
	"fmt"
	"log"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func main() {

	// refer fastdialer/options.go for options and customization
	options := fastdialer.DefaultOptions

	// Create new dialer using NewDialer(opts fastdialer.options)
	fd, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		panic(err)
	}

	// Configure Cache if required
	// memory based (also support Hybrid and Disk Cache)
	options.CacheType = fastdialer.Memory
	options.CacheMemoryMaxItems = 100

	ctx := context.Background()

	// To dial and create connection use
	// To create connection over TLS or older versions use
	// fd.DialTLS() or fd.DialZTLS()
	conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
	if err != nil || conn == nil {
		log.Fatalf("couldn't connect to target: %s", err)
	} else {
		fmt.Println("Connected: TCP stream created with www.projectdiscovery.io:80")
	}
	conn.Close()

	// To look up Host/ Get DNS details use
	data, err := fd.GetDNSData("www.projectdiscovery.io")
	if err != nil || data == nil {
		log.Fatalf("couldn't retrieve dns data: %s", err)
	}

	// To Print All Type of DNS Data use
	jsonData, err := data.JSON()
	if err != nil {
		log.Fatalf("failed to marshal json: %s", err)
	}
	fmt.Println(jsonData)

}
