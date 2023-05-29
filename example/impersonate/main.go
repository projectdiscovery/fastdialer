package main

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
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

	conn, err := fd.DialTLSWithConfigImpersonate(ctx, "tcp", target+":443", &tls.Config{InsecureSkipVerify: true}, impersonate.Random, nil)
	if err != nil || conn == nil {
		log.Fatalf("couldn't connect to target: %s", err)
	}
	defer conn.Close()
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
	log.Println(jsonData)
}
