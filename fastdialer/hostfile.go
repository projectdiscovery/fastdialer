package fastdialer

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimchansky/utfbom"
	"github.com/projectdiscovery/hmap/store/hybrid"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

func loadHostsFile(hm *hybrid.HybridMap) error {
	osHostsFilePath := os.ExpandEnv(filepath.FromSlash(HostsFilePath))

	if env, isset := os.LookupEnv("HOSTS_PATH"); isset && len(env) > 0 {
		osHostsFilePath = os.ExpandEnv(filepath.FromSlash(env))
	}

	file, err := os.Open(osHostsFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(utfbom.SkipOnly(file))
	for scanner.Scan() {
		ip, hosts := HandleLine(scanner.Text())
		if ip == "" || len(hosts) == 0 {
			continue
		}
		for _, host := range hosts {
			dnsdata := retryabledns.DNSData{Host: host, A: []string{ip}}
			dnsdataBytes, _ := dnsdata.Marshal()
			hm.Set(host, dnsdataBytes)
		}
	}

	return nil
}

const commentChar string = "#"

// HandleLine a hosts file line
func HandleLine(raw string) (ip string, hosts []string) {
	// ignore comment
	if IsComment(raw) {
		return
	}

	// trim comment
	if HasComment(raw) {
		commentSplit := strings.Split(raw, commentChar)
		raw = commentSplit[0]
	}

	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return
	}

	// not a valid ip
	ip = fields[0]
	if net.ParseIP(ip) == nil {
		return
	}

	hosts = fields[1:]

	return
}

// IsComment check if the file is a comment
func IsComment(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), commentChar)
}

// HasComment check if the line has a comment
func HasComment(raw string) bool {
	return strings.Contains(raw, commentChar)
}
