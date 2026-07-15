package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	toolVersion = "1.0.0"

	requestTimeout       = 15 * time.Second
	dnsTimeout           = 5 * time.Second
	globalScanTimeout    = 6 * time.Minute
	maxGlobalConcurrency = 20
	maxBodySize          = 5 * 1024 * 1024
	maxRetries           = 3
	nvdMinInterval       = 8 * time.Second

	exitClean        = 0
	exitNonCritical  = 1
	exitCriticalHigh = 2
	exitFatal        = 3
)

var (
	colorRed     = "\033[0;31m"
	colorGreen   = "\033[0;32m"
	colorYellow  = "\033[1;33m"
	colorMagenta = "\033[0;35m"
	colorCyan    = "\033[0;36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorReset   = "\033[0m"
)

func init() {
	fi, err := os.Stdout.Stat()
	isTTY := err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	if !isTTY || os.Getenv("NO_COLOR") != "" || os.Getenv("CI") != "" {
		colorRed, colorGreen, colorYellow = "", "", ""
		colorMagenta, colorCyan, colorBold = "", "", ""
		colorDim, colorReset = "", ""
	}
}

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
	SevError
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	case SevInfo:
		return "INFO"
	case SevError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

type Finding struct {
	Severity Severity
	Category string
	Message  string
	Path     string
	Evidence string
}

type Collector struct {
	mu     sync.Mutex
	items  []Finding
	counts [6]int
}

func NewCollector() *Collector { return &Collector{} }

func (col *Collector) Add(f Finding) {
	col.mu.Lock()
	defer col.mu.Unlock()
	col.items = append(col.items, f)
	col.counts[f.Severity]++
	printFinding(f)
}

func (col *Collector) Snapshot() ([]Finding, [6]int) {
	col.mu.Lock()
	defer col.mu.Unlock()
	out := make([]Finding, len(col.items))
	copy(out, col.items)
	return out, col.counts
}

type httpResult struct {
	StatusCode int
	Body       []byte
	Header     http.Header
}

type Client struct {
	hc        *http.Client
	userAgent string
	retries   int
	sem       chan struct{}
}

func NewClient(timeout time.Duration, maxConcurrent int) *Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	hc := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
	return &Client{
		hc:        hc,
		userAgent: "Mozilla/5.0 (compatible; WPfather/" + toolVersion + "; security-research)",
		retries:   maxRetries,
		sem:       make(chan struct{}, maxConcurrent),
	}
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"connection reset", "connection refused", "EOF", "broken pipe"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func (c *Client) doOnce(ctx context.Context, method, target string) (*httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	return &httpResult{StatusCode: resp.StatusCode, Body: body, Header: resp.Header}, nil
}

func (c *Client) requestOnce(ctx context.Context, method, target string) (*httpResult, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()
	return c.doOnce(ctx, method, target)
}

func (c *Client) Fetch(ctx context.Context, target string) (*httpResult, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		res, err := c.doOnce(ctx, http.MethodGet, target)
		<-c.sem

		switch {
		case err != nil:
			lastErr = err
			if !isTransient(err) {
				return nil, err
			}
		case res.StatusCode >= 500:
			lastErr = fmt.Errorf("server error: HTTP %d", res.StatusCode)
		default:
			return res, nil
		}

		if attempt < c.retries {
			backoff := time.Duration(attempt*attempt+1) * time.Second
			jitter := time.Duration(rand.Intn(500)) * time.Millisecond
			select {
			case <-time.After(backoff + jitter):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return nil, lastErr
}

func (c *Client) postXML(ctx context.Context, target, body string) (*httpResult, error) {
	var res *httpResult
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
		if err != nil {
			<-c.sem
			return nil, err
		}
		req.Header.Set("Content-Type", "text/xml")
		req.Header.Set("User-Agent", c.userAgent)
		resp, err := c.hc.Do(req)
		<-c.sem

		if err != nil {
			lastErr = err
			if !isTransient(err) {
				return nil, err
			}
		} else {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			resp.Body.Close()
			if rerr != nil {
				lastErr = rerr
			} else {
				res = &httpResult{StatusCode: resp.StatusCode, Body: b, Header: resp.Header}
				if res.StatusCode < 500 {
					return res, nil
				}
				lastErr = fmt.Errorf("server error: HTTP %d", res.StatusCode)
			}
		}

		if attempt < c.retries {
			backoff := time.Duration(attempt*attempt+1) * 800 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return res, lastErr
}

func (c *Client) TraceRedirects(ctx context.Context, target string) ([]string, string, error) {
	hops := []string{target}
	current := target
	noRedirect := &http.Client{
		Timeout:   c.hc.Timeout,
		Transport: c.hc.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for i := 0; i < 10; i++ {
		if ctx.Err() != nil {
			return hops, current, ctx.Err()
		}
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			return hops, current, ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			<-c.sem
			return hops, current, err
		}
		req.Header.Set("User-Agent", c.userAgent)
		resp, err := noRedirect.Do(req)
		<-c.sem
		if err != nil {
			return hops, current, err
		}
		loc := resp.Header.Get("Location")
		code := resp.StatusCode
		resp.Body.Close()

		if code >= 300 && code < 400 && loc != "" {
			next, rerr := resolveURL(current, loc)
			if rerr != nil {
				return hops, current, nil
			}
			current = next
			hops = append(hops, current)
			continue
		}
		break
	}
	return hops, current, nil
}

func resolveURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

func hostOf(raw string) string {
	p, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

func checkPathExists(ctx context.Context, c *Client, col *Collector, target, path string, sev Severity, category, message string) bool {
	full := target + path
	res, err := c.Fetch(ctx, full)
	if err != nil || (res.StatusCode != 200 && res.StatusCode != 403) || len(res.Body) == 0 {
		return false
	}
	if res.StatusCode == 403 {
		return false
	}
	col.Add(Finding{Severity: sev, Category: category, Message: message, Path: full})
	return true
}

func parallelStrings(ctx context.Context, items []string, workers int, fn func(string)) {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "%s[!] worker panic recovered: %v%s\n", colorRed, r, colorReset)
				}
			}()
			if ctx.Err() != nil {
				return
			}
			fn(it)
		}(item)
	}
	wg.Wait()
}

type RateLimiter struct {
	mu       sync.Mutex
	last     time.Time
	interval time.Duration
}

func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{interval: interval}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last.IsZero() {
		r.last = time.Now()
		return nil
	}
	if elapsed := time.Since(r.last); elapsed < r.interval {
		select {
		case <-time.After(r.interval - elapsed):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.last = time.Now()
	return nil
}

var nvdLimiter = NewRateLimiter(nvdMinInterval)

var domainRe = regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?$`)

func normalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("no domain provided")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	raw = strings.TrimRight(raw, "/")
	if !domainRe.MatchString(raw) {
		return "", fmt.Errorf("invalid domain format: %q (expected example.com or https://example.com)", raw)
	}
	return raw, nil
}

func promptDomain() string {
	fmt.Printf("%s📥 Your Domain: %s", colorBold, colorReset)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024), 1024)
	if !sc.Scan() {
		return ""
	}
	return sc.Text()
}

func confirmAuthorization(target string) bool {
	fmt.Printf("\n%sType 'yes' to confirm you are authorized to scan %s: %s", colorBold, target, colorReset)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 256), 256)
	if !sc.Scan() {
		return false
	}
	return strings.TrimSpace(strings.ToLower(sc.Text())) == "yes"
}

func preflight(ctx context.Context, c *Client, col *Collector, target string) bool {
	p, err := url.Parse(target)
	if err != nil {
		col.Add(Finding{Severity: SevCritical, Category: "preflight", Message: fmt.Sprintf("invalid target URL: %v", err), Path: target})
		return false
	}
	host := p.Hostname()

	dnsCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	ips, err := (&net.Resolver{}).LookupIPAddr(dnsCtx, host)
	if err != nil || len(ips) == 0 {
		col.Add(Finding{Severity: SevCritical, Category: "preflight", Message: fmt.Sprintf("DNS resolution failed for %s: %v", host, err), Path: host})
		return false
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	col.Add(Finding{Severity: SevInfo, Category: "preflight", Message: fmt.Sprintf("resolved %s -> %s", host, strings.Join(addrs, ", ")), Path: host})

	var res *httpResult
	var ferr error
	withSpinner(ctx, "📡 Connecting to "+target, func() {
		res, ferr = c.Fetch(ctx, target+"/")
	})
	if ferr != nil {
		col.Add(Finding{Severity: SevCritical, Category: "preflight", Message: fmt.Sprintf("cannot connect to %s: %v", target, ferr), Path: target})
		return false
	}
	col.Add(Finding{Severity: SevInfo, Category: "preflight", Message: fmt.Sprintf("target responded with HTTP %d", res.StatusCode), Path: target + "/"})
	return true
}

func scanRedirects(ctx context.Context, c *Client, col *Collector, target string) {
	hops, final, err := c.TraceRedirects(ctx, target)
	if err != nil {
		col.Add(Finding{Severity: SevError, Category: "redirects", Message: fmt.Sprintf("redirect trace failed: %v", err), Path: target})
		return
	}
	if len(hops) > 1 {
		col.Add(Finding{Severity: SevInfo, Category: "redirects", Message: fmt.Sprintf("followed %d redirect(s): %s", len(hops)-1, strings.Join(hops, " -> ")), Path: target})
	}
	origHost, finalHost := hostOf(target), hostOf(final)
	if origHost != "" && finalHost != "" && !strings.EqualFold(origHost, finalHost) {
		col.Add(Finding{Severity: SevMedium, Category: "redirects", Message: fmt.Sprintf("target redirects to a different host (%s) — scope may have changed", finalHost), Path: final})
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func scanTLS(ctx context.Context, c *Client, col *Collector, target string) {
	p, err := url.Parse(target)
	if err != nil || p.Scheme != "https" {
		col.Add(Finding{Severity: SevInfo, Category: "tls", Message: "target not using HTTPS — traffic is unencrypted", Path: target})
		return
	}
	host := p.Hostname()
	port := p.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS10,
	})
	if err != nil {
		col.Add(Finding{Severity: SevMedium, Category: "tls", Message: fmt.Sprintf("TLS handshake failed: %v", err), Path: host + ":" + port})
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	verStr := tlsVersionName(state.Version)
	if state.Version < tls.VersionTLS12 {
		col.Add(Finding{Severity: SevHigh, Category: "tls", Message: fmt.Sprintf("weak TLS protocol negotiated: %s", verStr), Path: host + ":" + port})
	} else {
		col.Add(Finding{Severity: SevInfo, Category: "tls", Message: fmt.Sprintf("TLS protocol: %s", verStr), Path: host + ":" + port})
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		switch {
		case days < 0:
			col.Add(Finding{Severity: SevCritical, Category: "tls", Message: fmt.Sprintf("certificate EXPIRED %d day(s) ago (%s)", -days, cert.NotAfter.Format("2006-01-02")), Path: host})
		case days < 14:
			col.Add(Finding{Severity: SevHigh, Category: "tls", Message: fmt.Sprintf("certificate expires soon: %d day(s) (%s)", days, cert.NotAfter.Format("2006-01-02")), Path: host})
		default:
			col.Add(Finding{Severity: SevInfo, Category: "tls", Message: fmt.Sprintf("certificate valid until %s", cert.NotAfter.Format("2006-01-02")), Path: host})
		}
		if len(state.PeerCertificates) == 1 {
			col.Add(Finding{Severity: SevMedium, Category: "tls", Message: "certificate appears self-signed (single certificate in chain)", Path: host})
		}
	}
}

func scanWAF(ctx context.Context, c *Client, col *Collector, target string) {
	res, err := c.Fetch(ctx, target+"/")
	if err != nil {
		col.Add(Finding{Severity: SevError, Category: "waf", Message: fmt.Sprintf("could not fetch homepage: %v", err), Path: target})
		return
	}
	signatures := map[string]string{
		"cf-ray":      "Cloudflare",
		"cf-cache":    "Cloudflare",
		"x-sucuri-id": "Sucuri",
		"x-sucuri":    "Sucuri",
		"x-iinfo":     "Imperva Incapsula",
		"x-akamai":    "Akamai",
		"x-amz-cf":    "AWS CloudFront",
		"x-cache":     "AWS CloudFront",
		"fastly":      "Fastly",
	}
	detected := map[string]bool{}
	for h := range res.Header {
		lh := strings.ToLower(h)
		for sig, name := range signatures {
			if strings.Contains(lh, sig) {
				detected[name] = true
			}
		}
	}
	server := strings.ToLower(res.Header.Get("Server"))
	for sig, name := range map[string]string{
		"cloudflare": "Cloudflare",
		"sucuri":     "Sucuri",
		"cloudfront": "AWS CloudFront",
		"fastly":     "Fastly",
		"akamai":     "Akamai",
	} {
		if strings.Contains(server, sig) {
			detected[name] = true
		}
	}
	if len(detected) == 0 {
		col.Add(Finding{Severity: SevInfo, Category: "waf", Message: "no WAF/CDN fingerprint detected", Path: target + "/"})
		return
	}
	names := make([]string, 0, len(detected))
	for n := range detected {
		names = append(names, n)
	}
	sort.Strings(names)
	col.Add(Finding{Severity: SevInfo, Category: "waf", Message: fmt.Sprintf("WAF/CDN detected: %s — later results may be filtered or incomplete", strings.Join(names, ", ")), Path: target + "/"})
}

var disallowRe = regexp.MustCompile(`(?im)^\s*Disallow:\s*(\S+)`)

func extractDisallowPaths(body string) []string {
	matches := disallowRe.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		p := strings.TrimSpace(m[1])
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func looksSensitive(path string) bool {
	lp := strings.ToLower(path)
	for _, k := range []string{"admin", "backup", "config", "wp-admin", "private", "secret", ".env", "database", "db", "install", "sql", "dump"} {
		if strings.Contains(lp, k) {
			return true
		}
	}
	return false
}

func joinPath(target, p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(target, "/") + p
}

func scanRobots(ctx context.Context, c *Client, col *Collector, target string) {
	for _, p := range []string{"/robots.txt", "/sitemap.xml", "/sitemap_index.xml"} {
		full := target + p
		res, err := c.Fetch(ctx, full)
		if err != nil || (res.StatusCode != 200 && res.StatusCode != 403) || len(res.Body) == 0 {
			continue
		}
		if res.StatusCode == 403 {
			continue
		}
		body := string(res.Body)
		col.Add(Finding{Severity: SevInfo, Category: "recon", Message: fmt.Sprintf("%s accessible (%d bytes)", p, len(body)), Path: full})
		if p == "/robots.txt" {
			for _, path := range extractDisallowPaths(body) {
				if looksSensitive(path) {
					col.Add(Finding{Severity: SevLow, Category: "recon", Message: "robots.txt discloses a potentially sensitive path", Path: joinPath(target, path)})
				}
			}
		}
	}
}

func scanHTTPMethods(ctx context.Context, c *Client, col *Collector, target string) {
	methods := []string{http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete, http.MethodConnect}
	var allowed []string
	var risky []string

	for _, method := range methods {
		res, err := c.requestOnce(ctx, method, target+"/")
		if err != nil {
			continue
		}
		if res.StatusCode != 405 && res.StatusCode != 501 {
			allowed = append(allowed, method)
			riskyMethods := map[string]bool{"PUT": true, "DELETE": true, "TRACE": true, "CONNECT": true}
			if riskyMethods[method] {
				risky = append(risky, method)
			}
		}
	}

	if len(risky) > 0 {
		col.Add(Finding{Severity: SevMedium, Category: "http-methods", Message: fmt.Sprintf("potentially risky HTTP methods enabled: %s", strings.Join(risky, ", ")), Path: target + "/"})
	} else if len(allowed) > 0 {
		col.Add(Finding{Severity: SevInfo, Category: "http-methods", Message: fmt.Sprintf("allowed methods: %s", strings.Join(allowed, ", ")), Path: target + "/"})
	}
}

func scanCookies(ctx context.Context, c *Client, col *Collector, target string) {
	res, err := c.Fetch(ctx, target+"/")
	if err != nil {
		return
	}
	for _, ck := range res.Header.Values("Set-Cookie") {
		lc := strings.ToLower(ck)
		name := ck
		if idx := strings.Index(ck, "="); idx > 0 {
			name = ck[:idx]
		}
		var missing []string
		if !strings.Contains(lc, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(lc, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !strings.Contains(lc, "samesite") {
			missing = append(missing, "SameSite")
		}
		if strings.Contains(lc, "path=") {
			pathMatch := regexp.MustCompile(`path=([^;]+)`).FindStringSubmatch(lc)
			if len(pathMatch) > 1 && pathMatch[1] != "/" {
				missing = append(missing, "Path=/")
			}
		} else {
			missing = append(missing, "Path=/")
		}
		if strings.HasPrefix(name, "__Secure-") && !strings.Contains(lc, "secure") {
			missing = append(missing, "Secure (required for __Secure- prefix)")
		}
		if strings.HasPrefix(name, "__Host-") && (!strings.Contains(lc, "secure") || !strings.Contains(lc, "path=/")) {
			missing = append(missing, "Secure and Path=/ (required for __Host- prefix)")
		}
		if len(missing) > 0 {
			col.Add(Finding{Severity: SevLow, Category: "cookies", Message: fmt.Sprintf("cookie %q missing flag(s): %s", name, strings.Join(missing, ", ")), Path: target + "/"})
		}
	}
}

var (
	wpVersionRe     = regexp.MustCompile(`(?i)WordPress\s+([0-9]+(?:\.[0-9]+){1,2})`)
	wpGeneratorRe   = regexp.MustCompile(`(?i)<meta name="generator" content="WordPress\s+([0-9.]+)"`)
	wpVersionFileRe = regexp.MustCompile(`(?i)\$wp_version\s*=\s*['"]([0-9.]+)['"]`)
)

type wpVersionCheckResp struct {
	Offers []struct {
		Version string `json:"version"`
	} `json:"offers"`
}

func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var na, nb int
		if i < len(pa) {
			na, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(pb[i])
		}
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func checkLatestWPVersion(ctx context.Context, c *Client, col *Collector, target, current string) {
	res, err := c.Fetch(ctx, "https://api.wordpress.org/core/version-check/1.7/")
	if err != nil || res.StatusCode != 200 {
		return
	}
	var parsed wpVersionCheckResp
	if err := json.Unmarshal(res.Body, &parsed); err != nil || len(parsed.Offers) == 0 {
		return
	}
	latest := parsed.Offers[0].Version
	if latest == "" || latest == current {
		return
	}
	if compareVersions(current, latest) < 0 {
		col.Add(Finding{Severity: SevMedium, Category: "core", Message: fmt.Sprintf("outdated WordPress core: running %s, latest is %s", current, latest), Path: target + "/"})
	}
}

func scanCore(ctx context.Context, c *Client, col *Collector, target string) {
	res, err := c.Fetch(ctx, target+"/")
	if err != nil {
		col.Add(Finding{Severity: SevError, Category: "core", Message: fmt.Sprintf("could not fetch homepage: %v", err), Path: target})
		return
	}
	body := string(res.Body)

	version := ""
	if m := wpGeneratorRe.FindStringSubmatch(body); len(m) > 1 {
		version = m[1]
	} else if m := wpVersionRe.FindStringSubmatch(body); len(m) > 1 {
		version = m[1]
	}
	if version == "" {
		if r, err := c.Fetch(ctx, target+"/wp-includes/version.php"); err == nil && r.StatusCode == 200 {
			if m := wpVersionFileRe.FindStringSubmatch(string(r.Body)); len(m) > 1 {
				version = m[1]
			}
		}
	}
	if version != "" {
		col.Add(Finding{Severity: SevLow, Category: "core", Message: fmt.Sprintf("WordPress version disclosed: %s", version), Path: target + "/"})
		checkLatestWPVersion(ctx, c, col, target, version)
	} else {
		col.Add(Finding{Severity: SevInfo, Category: "core", Message: "WordPress version not disclosed", Path: target + "/"})
	}

	if dbg, err := c.Fetch(ctx, target+"/?debug=true"); err == nil && dbg.StatusCode == 200 &&
		(bytes.Contains(dbg.Body, []byte("Fatal error")) || bytes.Contains(dbg.Body, []byte("Warning:")) || bytes.Contains(dbg.Body, []byte("Notice:"))) {
		col.Add(Finding{Severity: SevHigh, Category: "core", Message: "WP_DEBUG appears enabled — PHP errors/warnings exposed", Path: target + "/?debug=true"})
	}

	checkPathExists(ctx, c, col, target, "/readme.html", SevLow, "core", "readme.html exposed (confirms exact core files present)")
	checkPathExists(ctx, c, col, target, "/wp-admin/install.php", SevMedium, "core", "install.php is accessible — may allow re-running the installer")
	checkPathExists(ctx, c, col, target, "/wp-cron.php", SevLow, "core", "wp-cron.php directly accessible (potential DoS vector if unthrottled)")

	if xpb := res.Header.Get("X-Powered-By"); xpb != "" {
		col.Add(Finding{Severity: SevLow, Category: "core", Message: fmt.Sprintf("X-Powered-By header discloses: %s", xpb), Path: target + "/"})
	}
	if srv := res.Header.Get("Server"); srv != "" {
		col.Add(Finding{Severity: SevInfo, Category: "core", Message: fmt.Sprintf("Server header: %s", srv), Path: target + "/"})
	}
}

const (
	xmlrpcListMethods = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`
	xmlrpcPingbackTpl = `<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://127.0.0.1:80/</string></value></param><param><value><string>%s</string></value></param></params></methodCall>`
)

func scanXMLRPC(ctx context.Context, c *Client, col *Collector, target string) {
	endpoint := target + "/xmlrpc.php"
	res, err := c.postXML(ctx, endpoint, xmlrpcListMethods)
	if err != nil {
		col.Add(Finding{Severity: SevInfo, Category: "xmlrpc", Message: fmt.Sprintf("xmlrpc.php check failed: %v", err), Path: endpoint})
		return
	}
	if res.StatusCode != 200 {
		col.Add(Finding{Severity: SevInfo, Category: "xmlrpc", Message: fmt.Sprintf("XML-RPC not available (HTTP %d)", res.StatusCode), Path: endpoint})
		return
	}
	body := string(res.Body)
	if !strings.Contains(body, "methodResponse") {
		col.Add(Finding{Severity: SevInfo, Category: "xmlrpc", Message: "endpoint responded but does not look like valid XML-RPC", Path: endpoint})
		return
	}
	col.Add(Finding{Severity: SevHigh, Category: "xmlrpc", Message: "XML-RPC is enabled", Path: endpoint})
	if strings.Contains(body, "pingback.ping") {
		col.Add(Finding{Severity: SevHigh, Category: "xmlrpc", Message: "pingback.ping is available — potential SSRF/DDoS amplification vector", Path: endpoint})
	}
	if strings.Contains(body, "system.multicall") {
		col.Add(Finding{Severity: SevHigh, Category: "xmlrpc", Message: "system.multicall is available — enables amplified login brute-force", Path: endpoint})
	}
	if strings.Contains(body, "wp.getUsersBlogs") {
		col.Add(Finding{Severity: SevMedium, Category: "xmlrpc", Message: "wp.getUsersBlogs is available — usable for credential validation attacks", Path: endpoint})
	}
	col.Add(Finding{Severity: SevInfo, Category: "xmlrpc", Message: fmt.Sprintf("%d XML-RPC method(s) listed", strings.Count(body, "<string>")), Path: endpoint})
}

var faultCodeRe = regexp.MustCompile(`faultCode</name>\s*<value>\s*<int>(-?[0-9]+)</int>`)

func scanSSRF(ctx context.Context, c *Client, col *Collector, target string) {
	endpoint := target + "/xmlrpc.php"
	probe, err := c.Fetch(ctx, endpoint)
	if err != nil || (probe.StatusCode != 200 && probe.StatusCode != 405) {
		return
	}
	targets := []string{target + "/", "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/"}
	confirmed := false

	for _, t := range targets {
		res, err := c.postXML(ctx, endpoint, fmt.Sprintf(xmlrpcPingbackTpl, t))
		if err != nil {
			continue
		}
		if m := faultCodeRe.FindStringSubmatch(string(res.Body)); len(m) > 1 && m[1] == "0" {
			confirmed = true
			col.Add(Finding{Severity: SevHigh, Category: "ssrf", Message: fmt.Sprintf("SSRF confirmed via pingback.ping — server made a request to %s", t), Path: endpoint})
			break
		}
		if strings.Contains(string(res.Body), "48") {
			continue
		}
	}
	if !confirmed {
		col.Add(Finding{Severity: SevInfo, Category: "ssrf", Message: "pingback SSRF probe did not confirm (server may block internal targets)", Path: endpoint})
	}
}

type wpUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func scanUsers(ctx context.Context, c *Client, col *Collector, target string) {
	endpoint := target + "/wp-json/wp/v2/users"
	if res, err := c.Fetch(ctx, endpoint); err == nil && res.StatusCode == 200 {
		var users []wpUser
		if jerr := json.Unmarshal(res.Body, &users); jerr == nil && len(users) > 0 {
			col.Add(Finding{Severity: SevHigh, Category: "users", Message: fmt.Sprintf("REST API exposes %d user account(s)", len(users)), Path: endpoint})
			for _, u := range users {
				if u.Name != "" {
					col.Add(Finding{Severity: SevMedium, Category: "users", Message: fmt.Sprintf("username disclosed: %s (id=%d, slug=%s)", u.Name, u.ID, u.Slug), Path: endpoint})
				}
			}
		} else {
			col.Add(Finding{Severity: SevInfo, Category: "users", Message: "REST API users endpoint is protected or empty", Path: endpoint})
		}
	} else {
		col.Add(Finding{Severity: SevInfo, Category: "users", Message: "REST API users endpoint not accessible", Path: endpoint})
	}

	var mu sync.Mutex
	found := 0
	ids := make([]string, 20)
	for i := 1; i <= 20; i++ {
		ids[i-1] = strconv.Itoa(i)
	}
	parallelStrings(ctx, ids, 10, func(idStr string) {
		full := fmt.Sprintf("%s/?author=%s", target, idStr)
		res, err := c.requestOnce(ctx, http.MethodGet, full)
		if err != nil || res.StatusCode < 300 || res.StatusCode >= 400 {
			return
		}
		loc := res.Header.Get("Location")
		if loc == "" || !strings.Contains(loc, "/author/") {
			return
		}
		mu.Lock()
		found++
		mu.Unlock()
		col.Add(Finding{Severity: SevLow, Category: "users", Message: fmt.Sprintf("author enumeration: id=%s redirects to %s", idStr, loc), Path: full})
	})
	if found > 0 {
		col.Add(Finding{Severity: SevLow, Category: "users", Message: fmt.Sprintf("author-ID enumeration found %d valid account(s)", found), Path: target + "/?author=N"})
	}
}

var (
	pluginPathRe   = regexp.MustCompile(`wp-content/plugins/([a-zA-Z0-9_-]+)`)
	stableTagRe    = regexp.MustCompile(`(?i)Stable tag:\s*([0-9][0-9.]*)`)
	pluginNameRe   = regexp.MustCompile(`(?m)^===\s*(.+?)\s*===`)
	themePathRe    = regexp.MustCompile(`wp-content/themes/([a-zA-Z0-9_-]+)`)
	themeVersionRe = regexp.MustCompile(`(?i)Version:\s*([0-9][0-9.]*)`)
)

var commonPluginSlugs = []string{
	"revslider", "js_composer", "LayerSlider", "contact-form-7", "wordfence", "woocommerce", "elementor",
	"wordpress-seo", "photo-gallery", "akismet", "jetpack", "litespeed-cache", "updraftplus",
	"all-in-one-wp-migration", "duplicator", "wp-rocket", "w3-total-cache", "wpforms", "ninja-forms",
	"gravityforms", "mailchimp-for-wp", "redirection", "really-simple-ssl", "wp-super-cache",
	"autoptimize", "smush", "imagify", "ewww-image-optimizer", "sucuri-scanner", "ithemes-security",
	"all-in-one-wp-security", "wp-file-manager", "wp-optimize", "broken-link-checker",
	"google-site-kit", "monsterinsights", "wp-mail-smtp", "formidable", "tablepress", "polylang",
	"wpml", "loco-translate", "advanced-custom-fields", "custom-post-type-ui", "classic-editor",
	"tinymce-advanced", "enable-media-replace", "regenerate-thumbnails", "better-search-replace",
	"wp-reset", "wp-migrate-db", "query-monitor", "wp-crontrol", "user-switching", "health-check",
	"two-factor", "limit-login-attempts", "simple-history", "stream", "mainwp", "managewp",
	"infinitewp", "backwpup", "backupbuddy", "vaultpress", "blogvault", "wp-time-capsule",
	"xcloner", "wp-staging", "wpvivid", "boldgrid-backup", "total-upkeep", "snapshot", "wp-db-backup",
	"searchwp", "relevanssi", "facetwp", "ajax-search", "ivory-search", "fibosearch",
}

func severityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	case score > 0:
		return SevLow
	default:
		return SevInfo
	}
}

func sanitizeKeyword(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == ' ' || r == '-' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func lookupCVE(ctx context.Context, c *Client, col *Collector, product, version, path string) {
	if err := nvdLimiter.Wait(ctx); err != nil {
		return
	}
	keyword := sanitizeKeyword(product)
	if keyword == "" {
		return
	}
	endpoint := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + url.QueryEscape(keyword) + "&resultsPerPage=3"
	res, err := c.Fetch(ctx, endpoint)
	if err != nil {
		return
	}
	if res.StatusCode == 429 {
		time.Sleep(10 * time.Second)
		res, err = c.Fetch(ctx, endpoint)
		if err != nil || res.StatusCode != 200 {
			return
		}
	}
	if res.StatusCode != 200 {
		return
	}
	var parsed nvdResponse
	if err := json.Unmarshal(res.Body, &parsed); err != nil {
		return
	}
	for i, v := range parsed.Vulnerabilities {
		if i >= 3 {
			break
		}
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if len(desc) > 120 {
			desc = desc[:120] + "..."
		}
		sev := SevMedium
		scoreStr := "N/A"
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			score := v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			sev = severityFromCVSS(score)
			scoreStr = fmt.Sprintf("%.1f", score)
		}
		col.Add(Finding{
			Severity: sev,
			Category: "cve",
			Message:  fmt.Sprintf("%s (CVSS %s): %s", v.CVE.ID, scoreStr, desc),
			Path:     path,
			Evidence: fmt.Sprintf("product=%s version=%s", product, version),
		})
	}
}

func scanPlugins(ctx context.Context, c *Client, col *Collector, target string) {
	body := ""
	if res, err := c.Fetch(ctx, target+"/"); err == nil {
		body = string(res.Body)
	}

	found := map[string]bool{}
	for _, m := range pluginPathRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			found[m[1]] = true
		}
	}

	if len(found) == 0 {
		var mu sync.Mutex
		parallelStrings(ctx, commonPluginSlugs, 20, func(slug string) {
			full := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", target, slug)
			r, err := c.Fetch(ctx, full)
			if err != nil || r.StatusCode != 200 || len(r.Body) == 0 {
				return
			}
			mu.Lock()
			found[slug] = true
			mu.Unlock()
		})
	}

	if len(found) == 0 {
		col.Add(Finding{Severity: SevInfo, Category: "plugins", Message: "no plugins detected", Path: target + "/"})
		return
	}

	slugs := make([]string, 0, len(found))
	for s := range found {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)

	for _, slug := range slugs {
		readmeURL := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", target, slug)
		r, err := c.Fetch(ctx, readmeURL)
		if err != nil || r.StatusCode != 200 {
			col.Add(Finding{Severity: SevLow, Category: "plugins", Message: fmt.Sprintf("plugin detected: %s (version unknown)", slug), Path: readmeURL})
			continue
		}
		rbody := string(r.Body)
		name := slug
		if m := pluginNameRe.FindStringSubmatch(rbody); len(m) > 1 {
			name = strings.TrimSpace(m[1])
		}
		version := ""
		if m := stableTagRe.FindStringSubmatch(rbody); len(m) > 1 {
			version = strings.TrimSpace(m[1])
		}
		if version == "" {
			col.Add(Finding{Severity: SevLow, Category: "plugins", Message: fmt.Sprintf("plugin: %s (version unknown)", name), Path: readmeURL})
			continue
		}
		col.Add(Finding{Severity: SevLow, Category: "plugins", Message: fmt.Sprintf("plugin: %s v%s", name, version), Path: readmeURL})
		lookupCVE(ctx, c, col, name, version, readmeURL)
	}
	col.Add(Finding{Severity: SevInfo, Category: "plugins", Message: fmt.Sprintf("total plugins detected: %d", len(slugs)), Path: target + "/"})
}

func scanTheme(ctx context.Context, c *Client, col *Collector, target string) {
	res, err := c.Fetch(ctx, target+"/")
	if err != nil {
		return
	}
	m := themePathRe.FindStringSubmatch(string(res.Body))
	if len(m) < 2 {
		col.Add(Finding{Severity: SevInfo, Category: "theme", Message: "active theme not detected", Path: target + "/"})
		return
	}
	themeURL := fmt.Sprintf("%s/wp-content/themes/%s/", target, m[1])
	col.Add(Finding{Severity: SevInfo, Category: "theme", Message: fmt.Sprintf("active theme: %s", m[1]), Path: themeURL})

	styleURL := themeURL + "style.css"
	if r, err := c.Fetch(ctx, styleURL); err == nil && r.StatusCode == 200 {
		if vm := themeVersionRe.FindStringSubmatch(string(r.Body)); len(vm) > 1 {
			col.Add(Finding{Severity: SevLow, Category: "theme", Message: fmt.Sprintf("theme version: %s", vm[1]), Path: styleURL})
		}
	}
}

var sensitiveFiles = []string{
	"phpinfo.php", "info.php", "php.php", "i.php", "test.php",
	".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
	"wp-config.php.bak", "wp-config.php.old", "wp-config.php~", "wp-config.php.swp",
	"wp-config.php.save", "wp-config.php.orig", "wp-config.txt",
	"wp-config.php.backup", "wp-config.php.bak",
	"database.sql", "dump.sql", "db.sql", "backup.sql", "backup.zip", "backup.tar.gz",
	"db-backup.sql", "mysql.sql", "data.sql",
	".htaccess", ".htaccess.bak", ".htaccess.save", ".user.ini",
	"debug.log", "error_log", "error.log", "wp-debug.log",
	".DS_Store", ".well-known/security.txt",
	"composer.lock", "composer.json", "package-lock.json", "package.json",
	"robots.txt.bak", "sitemap.xml.bak",
}

func scanFiles(ctx context.Context, c *Client, col *Collector, target string) {
	found := 0
	var mu sync.Mutex
	parallelStrings(ctx, sensitiveFiles, 20, func(f string) {
		full := target + "/" + f
		res, err := c.Fetch(ctx, full)
		if err != nil || (res.StatusCode != 200 && res.StatusCode != 403) || len(res.Body) == 0 {
			return
		}
		if res.StatusCode == 403 {
			return
		}
		mu.Lock()
		found++
		mu.Unlock()
		col.Add(Finding{Severity: SevCritical, Category: "files", Message: fmt.Sprintf("sensitive file exposed: /%s", f), Path: full})
	})
	if found == 0 {
		col.Add(Finding{Severity: SevInfo, Category: "files", Message: "no sensitive files exposed from checklist", Path: target + "/"})
	}
}

var commonDirs = []string{
	"wp-content", "wp-content/uploads", "wp-content/plugins", "wp-content/themes",
	"wp-includes", "wp-content/backup", "backup", "uploads", "files", "images",
	"wp-admin", "wp-content/cache", "wp-content/languages", "wp-content/mu-plugins",
}

func scanDirs(ctx context.Context, c *Client, col *Collector, target string) {
	patterns := []string{
		"index of /",
		"[to parent directory]",
		"directory: /",
		"parent directory",
		"<title>index of",
	}
	parallelStrings(ctx, commonDirs, 15, func(d string) {
		full := target + "/" + d + "/"
		res, err := c.Fetch(ctx, full)
		if err != nil || res.StatusCode != 200 {
			return
		}
		bodyLower := strings.ToLower(string(res.Body))
		for _, pattern := range patterns {
			if strings.Contains(bodyLower, pattern) {
				col.Add(Finding{Severity: SevMedium, Category: "dirs", Message: fmt.Sprintf("directory listing enabled: /%s/", d), Path: full})
				break
			}
		}
	})
}

type headerCheck struct {
	header string
	label  string
}

var securityHeaders = []headerCheck{
	{"Strict-Transport-Security", "HSTS"},
	{"Content-Security-Policy", "CSP"},
	{"X-Frame-Options", "clickjacking protection"},
	{"X-Content-Type-Options", "MIME-sniffing protection"},
	{"Referrer-Policy", "referrer leak protection"},
	{"Permissions-Policy", "permissions policy"},
}

func scanHeaders(ctx context.Context, c *Client, col *Collector, target string) {
	res, err := c.Fetch(ctx, target+"/")
	if err != nil {
		col.Add(Finding{Severity: SevError, Category: "headers", Message: fmt.Sprintf("could not fetch headers: %v", err), Path: target})
		return
	}
	present := 0
	for _, h := range securityHeaders {
		if res.Header.Get(h.header) != "" {
			present++
		} else {
			col.Add(Finding{Severity: SevMedium, Category: "headers", Message: fmt.Sprintf("missing security header: %s (%s)", h.header, h.label), Path: target + "/"})
		}
	}
	col.Add(Finding{Severity: SevInfo, Category: "headers", Message: fmt.Sprintf("security headers: %d/%d present", present, len(securityHeaders)), Path: target + "/"})
}

var (
	internalIPRe = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	emailRe      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	googleAPIRe  = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	nonceRe      = regexp.MustCompile(`"nonce":"[^"]+"`)
	awsKeyRe     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	privateKeyRe = regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)
)

func scanLeaks(ctx context.Context, c *Client, col *Collector, target string) {
	res, err := c.Fetch(ctx, target+"/")
	if err != nil {
		return
	}
	body := string(res.Body)

	if m := internalIPRe.FindString(body); m != "" {
		col.Add(Finding{Severity: SevHigh, Category: "leaks", Message: fmt.Sprintf("internal IP address leaked: %s", m), Path: target + "/"})
	}
	seen := map[string]bool{}
	count := 0
	for _, m := range emailRe.FindAllString(body, -1) {
		if seen[m] || count >= 5 {
			continue
		}
		seen[m] = true
		count++
		col.Add(Finding{Severity: SevLow, Category: "leaks", Message: fmt.Sprintf("email address disclosed: %s", m), Path: target + "/"})
	}
	if googleAPIRe.MatchString(body) {
		col.Add(Finding{Severity: SevHigh, Category: "leaks", Message: "Google API key pattern found in page source", Path: target + "/"})
	}
	if awsKeyRe.MatchString(body) {
		col.Add(Finding{Severity: SevCritical, Category: "leaks", Message: "AWS Access Key ID pattern found in page source", Path: target + "/"})
	}
	if privateKeyRe.MatchString(body) {
		col.Add(Finding{Severity: SevCritical, Category: "leaks", Message: "Private key found in page source", Path: target + "/"})
	}
	if nonceRe.MatchString(body) {
		col.Add(Finding{Severity: SevMedium, Category: "leaks", Message: "WordPress nonce token present in page source", Path: target + "/"})
	}
}

type scanStep struct {
	name string
	fn   func(context.Context, *Client, *Collector, string)
}

func runStepSafely(col *Collector, name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			col.Add(Finding{Severity: SevError, Category: strings.ToLower(name), Message: fmt.Sprintf("module panicked and was skipped: %v", r)})
		}
	}()
	fn()
}

func runPipeline(ctx context.Context, c *Client, col *Collector, target string) {
	steps := []scanStep{
		{"Redirect Chain", scanRedirects},
		{"TLS/SSL", scanTLS},
		{"WAF/CDN Fingerprint", scanWAF},
		{"robots.txt & sitemap", scanRobots},
		{"HTTP Methods", scanHTTPMethods},
		{"Cookie Flags", scanCookies},
		{"WordPress Core", scanCore},
		{"XML-RPC", scanXMLRPC},
		{"Users", scanUsers},
		{"Plugins & CVEs", scanPlugins},
		{"Theme", scanTheme},
		{"Sensitive Files", scanFiles},
		{"Directory Listing", scanDirs},
		{"Security Headers", scanHeaders},
		{"Info Leaks", scanLeaks},
		{"SSRF Confirmation", scanSSRF},
	}

	total := len(steps)
	for i, s := range steps {
		if ctx.Err() != nil {
			col.Add(Finding{Severity: SevError, Category: "pipeline", Message: fmt.Sprintf("scan cancelled/timed out before step %q", s.name), Path: target})
			return
		}
		printProgress(i+1, total, s.name)
		step := s
		runStepSafely(col, step.name, func() {
			step.fn(ctx, c, col, target)
		})
	}
}

func severityStyle(s Severity) (icon, color string) {
	switch s {
	case SevCritical:
		return "🔴", colorRed
	case SevHigh:
		return "🟠", colorYellow
	case SevMedium:
		return "🟡", colorYellow
	case SevLow:
		return "🟢", colorGreen
	case SevInfo:
		return "ℹ️", colorCyan
	case SevError:
		return "⚠️", colorYellow
	default:
		return "•", colorReset
	}
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func withSpinner(ctx context.Context, label string, fn func()) {
	if colorReset == "" {
		fmt.Printf("%s...\n", label)
		fn()
		return
	}
	done := make(chan struct{})
	go func() {
		i := 0
		ticker := time.NewTicker(90 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Printf("\r%s%s%s %s ", colorCyan, spinnerFrames[i%len(spinnerFrames)], colorReset, label)
				i++
			}
		}
	}()
	fn()
	close(done)
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(label)+6))
}

func animateBoot() {
	label := "🛠️  Initializing WPFATHER"
	if colorReset == "" {
		return
	}
	for _, dots := range []string{".", "..", "..."} {
		fmt.Printf("\r%s%s%s%s", colorCyan, label, dots, colorReset)
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(label)+5))
}

var stepEmoji = map[string]string{
	"Redirect Chain":       "🔀",
	"TLS/SSL":              "🔒",
	"WAF/CDN Fingerprint":  "🛡️",
	"robots.txt & sitemap": "🤖",
	"HTTP Methods":         "🔧",
	"Cookie Flags":         "🍪",
	"WordPress Core":       "🧬",
	"XML-RPC":              "📡",
	"Users":                "👤",
	"Plugins & CVEs":       "🔌",
	"Theme":                "🎨",
	"Sensitive Files":      "📂",
	"Directory Listing":    "📁",
	"Security Headers":     "🛡️",
	"Info Leaks":           "💧",
	"SSRF Confirmation":    "🎯",
}

var categoryEmoji = map[string]string{
	"preflight":    "📡",
	"redirects":    "🔀",
	"tls":          "🔒",
	"waf":          "🛡️",
	"recon":        "🤖",
	"http-methods": "🔧",
	"cookies":      "🍪",
	"core":         "🧬",
	"xmlrpc":       "📡",
	"ssrf":         "🎯",
	"users":        "👤",
	"plugins":      "🔌",
	"theme":        "🎨",
	"files":        "📂",
	"dirs":         "📁",
	"headers":      "🛡️",
	"leaks":        "💧",
	"cve":          "🧨",
	"pipeline":     "⏱️",
}

func printFinding(f Finding) {
	icon, color := severityStyle(f.Severity)
	catIcon := categoryEmoji[f.Category]
	if catIcon == "" {
		catIcon = "•"
	}
	fmt.Printf("  %s%s [%s]%s %s %s\n", color, icon, f.Severity, colorReset, catIcon, f.Message)
	if f.Path != "" {
		fmt.Printf("      %s└─ %s%s\n", colorDim, f.Path, colorReset)
	}
	if f.Evidence != "" {
		fmt.Printf("      %s   %s%s\n", colorDim, f.Evidence, colorReset)
	}
}

func printProgress(i, total int, name string) {
	emoji := stepEmoji[name]
	if emoji == "" {
		emoji = "🔎"
	}
	fmt.Printf("\n%s[%d/%d] %s %s...%s\n", colorBold, i, total, emoji, name, colorReset)
}

func printBanner() {
	animateBoot()
	fmt.Print(colorRed)
	fmt.Println(`╔══════════════════════════════════════════════════════════════╗`)
	fmt.Println(`║                  🛡️  WPFATHER  v` + toolVersion + `  🛡️                  ║`)
	fmt.Println(`║           WordPress Security Reconnaissance Tool 🔎             ║`)
	fmt.Println(`║                   by @ps1-blacklist                            ║`)
	fmt.Println(`╚══════════════════════════════════════════════════════════════╝`)
	fmt.Print(colorReset)
	fmt.Println()
	fmt.Println("⚖️  Only scan systems you own or are explicitly authorized to test.")
	fmt.Println("   Unauthorized scanning may be illegal in your jurisdiction.")
}

func computeRiskScore(counts [6]int) int {
	score := 0
	score += counts[SevCritical] * 30
	score += counts[SevHigh] * 15
	score += counts[SevMedium] * 5
	score += counts[SevLow] * 1
	if score > 100 {
		score = 100
	}
	return score
}

func computeExitCode(col *Collector) int {
	_, counts := col.Snapshot()
	if counts[SevCritical] > 0 || counts[SevHigh] > 0 {
		return exitCriticalHigh
	}
	if counts[SevMedium] > 0 || counts[SevLow] > 0 {
		return exitNonCritical
	}
	return exitClean
}

func printSummary(col *Collector, start time.Time, target string) {
	_, counts := col.Snapshot()
	duration := time.Since(start).Round(time.Second)
	score := computeRiskScore(counts)
	scoreColor := colorGreen
	if score >= 30 {
		scoreColor = colorYellow
	}
	if score >= 60 {
		scoreColor = colorRed
	}

	scoreEmoji := "✅"
	if score >= 30 {
		scoreEmoji = "⚠️"
	}
	if score >= 60 {
		scoreEmoji = "🚨"
	}

	fmt.Printf("\n%s%s📊 ── SCAN SUMMARY ─────────────────────────%s\n", colorBold, colorMagenta, colorReset)
	fmt.Printf("🎯 Target:     %s\n", target)
	fmt.Printf("⏱️  Duration:   %s\n", duration)
	fmt.Printf("🔍 Findings:   %s🔴 Critical %d%s  %s🟠 High %d%s  %s🟡 Medium %d%s  %s🟢 Low %d%s  ℹ️  Info %d  ⚠️  Errors %d\n",
		colorRed, counts[SevCritical], colorReset,
		colorYellow, counts[SevHigh], colorReset,
		colorYellow, counts[SevMedium], colorReset,
		colorGreen, counts[SevLow], colorReset,
		counts[SevInfo], counts[SevError])
	fmt.Printf("%s Risk Score: %s%d/100%s\n", scoreEmoji, scoreColor, score, colorReset)
	fmt.Printf("%s%s─────────────────────────────────────────────%s\n", colorBold, colorMagenta, colorReset)
}

func main() {
	printBanner()

	raw := promptDomain()
	target, err := normalizeTarget(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s❌ %v%s\n", colorRed, err, colorReset)
		os.Exit(exitFatal)
	}

	if !confirmAuthorization(target) {
		fmt.Fprintln(os.Stderr, "Authorization not confirmed. Aborting.")
		os.Exit(exitFatal)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, globalScanTimeout)
	defer cancel()

	client := NewClient(requestTimeout, maxGlobalConcurrency)
	col := NewCollector()
	start := time.Now()

	fmt.Println()
	if !preflight(ctx, client, col, target) {
		printSummary(col, start, target)
		os.Exit(exitFatal)
	}

	fmt.Printf("\n%s🚀 Starting scan...%s\n", colorBold, colorReset)
	runPipeline(ctx, client, col, target)

	printSummary(col, start, target)
	os.Exit(computeExitCode(col))
}