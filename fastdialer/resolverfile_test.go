package fastdialer

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
)

func writeResolverFile(t *testing.T, content string) string {
	t.Helper()

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "resolv.conf")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	return path
}

func TestLoadResolverFile_ParsesResolversSearchAndNdots(t *testing.T) {
	resolvPath := writeResolverFile(t, `
# comment line
nameserver 1.1.1.1
nameserver 8.8.8.8
search example.com corp.local example.com
domain should.not.be.used
options ndots:2
`)

	t.Setenv("RESOLVERS_PATH", resolvPath)
	opts := Options{Ndots: 5, MaxResolverEntries: 1}
	config, err := loadResolverFile(opts)
	require.NoError(t, err)

	require.Equal(t, []string{"1.1.1.1:53"}, config.Resolvers, "respect MaxResolverEntries limit")
	require.Equal(t, []string{"example.com", "corp.local"}, config.SearchDomains, "dedupe and preserve order")
	require.Equal(t, 2, config.Ndots, "ndots option should override default/options value")
}

func TestLoadResolverFile_UsesDomainWhenSearchMissing(t *testing.T) {
	resolvPath := writeResolverFile(t, `
nameserver 9.9.9.9
domain example.org
`)

	t.Setenv("RESOLVERS_PATH", resolvPath)
	opts := Options{Ndots: 1, MaxResolverEntries: 10}
	config, err := loadResolverFile(opts)
	require.NoError(t, err)

	require.Equal(t, []string{"9.9.9.9:53"}, config.Resolvers)
	require.Equal(t, []string{"example.org"}, config.SearchDomains)
	require.Equal(t, 1, config.Ndots)
}

type mockDNS struct {
	answers map[string]string
	queries []string
	mu      sync.Mutex
}

func (m *mockDNS) handler(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	if len(r.Question) == 0 {
		_ = w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	name := dns.CanonicalName(q.Name)
	trimmed := name[:len(name)-1] // strip trailing dot

	m.mu.Lock()
	m.queries = append(m.queries, trimmed)
	m.mu.Unlock()

	if ip, ok := m.answers[trimmed]; ok {
		rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", name, ip))
		msg.Answer = append(msg.Answer, rr)
	} else {
		msg.Rcode = dns.RcodeNameError
	}

	_ = w.WriteMsg(msg)
}

func startMockDNSServer(t *testing.T, answers map[string]string) (addr string, mock *mockDNS, shutdown func()) {
	t.Helper()

	m := &mockDNS{answers: answers}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(m.handler)}
	done := make(chan struct{})

	go func() {
		_ = srv.ActivateAndServe()
		close(done)
	}()

	shutdown = func() {
		_ = srv.Shutdown()
		_ = pc.Close()
		<-done
	}

	return pc.LocalAddr().String(), m, shutdown
}

func newTestDNSClient(t *testing.T, resolver string) *retryabledns.Client {
	t.Helper()

	client, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: []string{resolver},
		MaxRetries:    1,
		Timeout:       2 * time.Second,
	})
	require.NoError(t, err)

	return client
}

func TestResolveWithSearch_UsesSearchDomainsAndNdots(t *testing.T) {
	t.Parallel()

	answers := map[string]string{
		"short.example.com": "192.0.2.10",
		"a.b.example.com":   "192.0.2.20",
		"foo.bar":           "192.0.2.30",
	}

	resolverAddr, mock, shutdown := startMockDNSServer(t, answers)
	defer shutdown()

	client := newTestDNSClient(t, resolverAddr)
	d := &Dialer{
		dnsclient:     client,
		searchDomains: []string{"example.com", "svc.local"},
		ndots:         1,
		options:       &Options{EnableFallback: false},
	}

	data, err := d.resolveWithSearch("short")
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.10"}, data.A)

	// For ndots=1, a name with a dot should be tried as-is first.
	d.ndots = 1
	mock.mu.Lock()
	mock.queries = nil
	mock.mu.Unlock()

	data, err = d.resolveWithSearch("a.b")
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.20"}, data.A)

	// Ensure query order: absolute first, then search expansion.
	mock.mu.Lock()
	queriesCopy := dedupeStrings(mock.queries)
	mock.mu.Unlock()
	require.Equal(t, []string{"a.b", "a.b.example.com"}, queriesCopy)

	// Trailing dot skips search-domain expansion.
	mock.mu.Lock()
	mock.queries = nil
	mock.mu.Unlock()

	data, err = d.resolveWithSearch("foo.bar.")
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.30"}, data.A)

	mock.mu.Lock()
	queriesCopy = dedupeStrings(mock.queries)
	mock.mu.Unlock()

	require.Equal(t, []string{"foo.bar"}, queriesCopy)
}
