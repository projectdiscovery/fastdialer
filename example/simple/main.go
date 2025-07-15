package main

import (
	"context"
	"fmt"
	"log"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func main() {
	options := fastdialer.DefaultOptions

	// Create new dialer using NewDialer(opts fastdialer.options)
	fd, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Configure Cache if required
	// memory based (also support Hybrid and Disk Cache)
	options.CacheType = fastdialer.Memory
	options.CacheMemoryMaxItems = 100

	ctx := context.Background()

	target := "www.projectdiscovery.io"

	conn, err := fd.DialTLS(ctx, "tcp", target+":443")
	if err != nil || conn == nil {
		log.Fatalf("couldn't connect to target: %s", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("failed to close connection: %s", err)
		}
	}()
	log.Println("connected to the target")

	// To look up Host/ Get DNS details use
	data, err := fd.GetDNSData(target)
	if err != nil || data == nil {
		log.Fatalf("couldn't retrieve dns data: %s", err)
	}

	// To Print All Type of DNS Data use
	jsonData, err := data.JSON()
	if err != nil {
		log.Fatalf("failed to marshal json: %s", err)
	}
	fmt.Print(jsonData)
}
