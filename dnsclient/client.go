package dnsclient

import (
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Client struct {
	resolvers  []string
	maxRetries int
}

func New(baseResolvers []string, maxRetries int) (*Client, error) {
	rand.Seed(time.Now().UnixNano())
	client := Client{maxRetries: maxRetries}
	// fails on non unix systems so we just don't care
	resolvers, _ := ReadResolveConfig("/etc/resolv.conf")
	client.resolvers = append(client.resolvers, resolvers...)
	client.resolvers = append(client.resolvers, baseResolvers...)
	return &client, nil
}

func (c *Client) Resolve(host string) (data *DNSData, err error) {
	data = &DNSData{}
	err = c.query(host, dns.TypeA, data)
	if err != nil {
		return
	}

	err = c.query(host, dns.TypeAAAA, data)
	return
}

func (c *Client) query(host string, queryType uint16, data *DNSData) error {
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  queryType,
		Qclass: dns.ClassINET,
	}
	resolver := c.resolvers[rand.Intn(len(c.resolvers))]
	for i := 0; i < c.maxRetries; i++ {
		answer, err := dns.Exchange(msg, resolver)
		if err != nil {
			continue
		}
		if answer != nil && answer.Rcode != dns.RcodeSuccess {
			return errors.New(dns.RcodeToString[answer.Rcode])
		}

		for _, record := range answer.Answer {
			switch t := record.(type) {
			case *dns.A:
				ip := t.A.String()
				if ip != "" {
					data.IP4s = append(data.IP4s, t.A.String())
				}
			case *dns.AAAA:
				ip := t.AAAA.String()
				if ip != "" {
					data.IP6s = append(data.IP6s, t.AAAA.String())
				}
			case *dns.CNAME:
				if queryType == dns.TypeA && t.Target != "" {
					data.CNAMEs = append(data.CNAMEs, strings.TrimSuffix(t.Target, "."))
				}
			}
		}

		break
	}

	return nil
}
