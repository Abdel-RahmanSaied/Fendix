package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"gopkg.in/yaml.v3"
)

// CommonPaths is a hardcoded list of frequently found API paths to brute-force.
var CommonPaths = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/api/health", "/api/status", "/api/ping",
	"/api/v1/users", "/api/v1/user", "/api/v1/me",
	"/api/v1/accounts", "/api/v1/auth", "/api/v1/login",
	"/api/v1/logout", "/api/v1/register", "/api/v1/signup",
	"/api/v1/token", "/api/v1/refresh",
	"/api/v1/admin", "/api/v1/config", "/api/v1/settings",
	"/api/v1/products", "/api/v1/orders", "/api/v1/items",
	"/api/v1/search", "/api/v1/upload", "/api/v1/files",
	"/health", "/healthz", "/ready", "/readyz",
	"/status", "/ping", "/info", "/version",
	"/swagger.json", "/swagger/", "/swagger-ui/",
	"/openapi.json", "/openapi.yaml",
	"/api-docs", "/docs", "/graphql",
	"/metrics", "/actuator", "/actuator/health",
	"/v1", "/v2", "/v3",
	"/users", "/admin", "/auth", "/login",
	"/.well-known/openapi.yaml", "/.well-known/openapi.json",
	"/robots.txt", "/sitemap.xml",
}

// apiPathRe matches patterns like "/api/something" or "'/api/v1/users'" in JS source.
var apiPathRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d+)/[a-zA-Z0-9/_\-{}]+)["'` + "`" + `]`)

// scriptSrcRe matches <script src="..."> tags.
var scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

// Crawler discovers API endpoints using multiple strategies.
type Crawler struct {
	client *http.Client
	cfg    *models.ScanConfig
	seen   map[string]bool
}

// NewCrawler creates a Crawler with an HTTP client configured from scan config.
func NewCrawler(cfg *models.ScanConfig) *Crawler {
	return &Crawler{
		client: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
		cfg:  cfg,
		seen: make(map[string]bool),
	}
}

// CrawlEndpoints discovers endpoints using all available strategies in priority order:
// 1. OpenAPI spec parsing (if --spec provided)
// 2. JavaScript source analysis (if --url provided)
// 3. Common path brute-force (if --url provided)
// Returns a deduplicated, sorted list of endpoints.
func (c *Crawler) CrawlEndpoints(ctx context.Context) ([]Endpoint, error) {
	var endpoints []Endpoint

	if c.cfg.SpecPath != "" {
		specEndpoints, err := c.fromSpec(ctx)
		if err != nil {
			slog.Warn("spec parsing failed, continuing with other strategies", "error", err)
		} else {
			endpoints = append(endpoints, specEndpoints...)
		}
	}

	if c.cfg.URL != "" {
		jsEndpoints, err := c.fromJS(ctx)
		if err != nil {
			slog.Debug("JS discovery failed", "error", err)
		} else {
			endpoints = append(endpoints, jsEndpoints...)
		}

		bruteEndpoints, err := c.fromBruteForce(ctx)
		if err != nil {
			slog.Debug("brute-force discovery failed", "error", err)
		} else {
			endpoints = append(endpoints, bruteEndpoints...)
		}
	}

	deduped := c.deduplicate(endpoints)
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Path != deduped[j].Path {
			return deduped[i].Path < deduped[j].Path
		}
		return deduped[i].Method < deduped[j].Method
	})

	slog.Info("endpoint discovery complete", "total", len(deduped))
	return deduped, nil
}

// fromSpec parses an OpenAPI 2.0/3.x spec and extracts all path+method combinations.
// Accepts both local file paths and HTTP/HTTPS URLs. URL form is needed because
// many real services publish their spec at /openapi.json or /swagger.json — users
// would otherwise have to curl-then-pass, and v0.1 silently fell back to brute-force
// when given a URL (TASK-082).
func (c *Crawler) fromSpec(ctx context.Context) ([]Endpoint, error) {
	data, isJSON, err := c.loadSpec(ctx, c.cfg.SpecPath)
	if err != nil {
		return nil, err
	}

	var spec map[string]interface{}
	if isJSON {
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing JSON spec: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing YAML spec: %w", err)
		}
	}

	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("spec has no 'paths' field or invalid format")
	}

	baseURL := c.specBaseURL(spec)
	var endpoints []Endpoint

	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true,
		"delete": true, "head": true, "options": true,
	}

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		// OpenAPI/Swagger lets path-level `parameters` apply to every operation
		// under that path; operation-level `parameters` add to (and may override
		// by name) the path-level set. Capture path-level once outside the
		// per-method loop.
		pathLevelParams := extractParamsList(methodMap["parameters"])

		for method, op := range methodMap {
			method = strings.ToLower(method)
			if !httpMethods[method] {
				continue
			}
			opMap, _ := op.(map[string]interface{})
			opParams := extractParamsList(opMap["parameters"])

			ep := Endpoint{
				Method:  strings.ToUpper(method),
				Path:    path,
				FullURL: baseURL + path,
				Params:  mergeParams(extractPathParams(path), pathLevelParams, opParams),
			}
			endpoints = append(endpoints, ep)
		}
	}

	slog.Info("endpoints from spec", "count", len(endpoints), "spec", c.cfg.SpecPath)
	return endpoints, nil
}

// loadSpec reads a spec from either a local file path or an HTTP/HTTPS URL.
// Returns the raw bytes and whether the format is JSON (vs YAML).
//
// Format detection is layered: explicit .json/.yaml suffix first, then
// HTTP Content-Type header, finally first non-whitespace byte ('{' or '[' = JSON).
// We don't fall back to "always YAML" even though yaml.Unmarshal accepts JSON,
// because the existing tests assert the JSON path produces JSON-typed errors.
func (c *Crawler) loadSpec(ctx context.Context, src string) (data []byte, isJSON bool, err error) {
	lower := strings.ToLower(src)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return c.fetchSpec(ctx, src)
	}
	data, err = os.ReadFile(src)
	if err != nil {
		return nil, false, fmt.Errorf("reading spec file %s: %w", src, err)
	}
	return data, strings.HasSuffix(lower, ".json"), nil
}

// fetchSpec downloads a spec from an HTTP/HTTPS URL using the crawler's HTTP
// client (so --timeout applies). 4xx/5xx responses are surfaced as errors.
func (c *Crawler) fetchSpec(ctx context.Context, src string) (data []byte, isJSON bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, false, fmt.Errorf("building spec request: %w", err)
	}
	// Hint preference but don't restrict — many specs are served as text/plain or octet-stream.
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetching spec from %s: %w", src, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("fetching spec from %s: HTTP %d", src, resp.StatusCode)
	}

	const maxSpecBytes = 50 << 20 // 50 MB; GitHub's spec is ~12 MB so this leaves headroom
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSpecBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("reading spec body: %w", err)
	}
	if int64(len(body)) > maxSpecBytes {
		return nil, false, fmt.Errorf("spec too large (>%d bytes) from %s", maxSpecBytes, src)
	}

	// Format detection: URL suffix > Content-Type > first non-whitespace byte.
	lowerSrc := strings.ToLower(src)
	switch {
	case strings.HasSuffix(lowerSrc, ".json"):
		isJSON = true
	case strings.HasSuffix(lowerSrc, ".yaml") || strings.HasSuffix(lowerSrc, ".yml"):
		isJSON = false
	default:
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		switch {
		case strings.Contains(ct, "json"):
			isJSON = true
		case strings.Contains(ct, "yaml") || strings.Contains(ct, "yml"):
			isJSON = false
		default:
			isJSON = looksLikeJSON(body)
		}
	}

	return body, isJSON, nil
}

// looksLikeJSON returns true if the first non-whitespace byte is '{' or '['.
// This is the canonical JSON-vs-YAML sniff used by parsers when no other
// signal is available (suffix, Content-Type).
func looksLikeJSON(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// specBaseURL extracts the base URL from an OpenAPI spec.
// Supports both OpenAPI 3.x (servers[0].url) and Swagger 2.0 (host + basePath).
func (c *Crawler) specBaseURL(spec map[string]interface{}) string {
	// Prefer explicit --url flag
	if c.cfg.URL != "" {
		return strings.TrimRight(c.cfg.URL, "/")
	}

	// OpenAPI 3.x: servers[0].url
	if servers, ok := spec["servers"].([]interface{}); ok && len(servers) > 0 {
		if srv, ok := servers[0].(map[string]interface{}); ok {
			if u, ok := srv["url"].(string); ok {
				return strings.TrimRight(u, "/")
			}
		}
	}

	// Swagger 2.0: host + basePath
	host, _ := spec["host"].(string)
	basePath, _ := spec["basePath"].(string)
	scheme := "https"
	if schemes, ok := spec["schemes"].([]interface{}); ok && len(schemes) > 0 {
		if s, ok := schemes[0].(string); ok {
			scheme = s
		}
	}
	if host != "" {
		return fmt.Sprintf("%s://%s%s", scheme, host, strings.TrimRight(basePath, "/"))
	}

	return "http://localhost"
}

// fromJS fetches the base URL page, extracts <script> sources,
// downloads each JS file, and extracts API path patterns.
func (c *Crawler) fromJS(ctx context.Context) ([]Endpoint, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", c.cfg.URL, err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching base URL %s: %w", c.cfg.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var endpoints []Endpoint
	baseURL := strings.TrimRight(c.cfg.URL, "/")

	// Extract paths directly from HTML/JSON response
	for _, match := range apiPathRe.FindAllSubmatch(body, -1) {
		path := string(match[1])
		endpoints = append(endpoints, Endpoint{
			Method:  "GET",
			Path:    path,
			FullURL: baseURL + path,
			Params:  extractPathParams(path),
		})
	}

	// Find and fetch script sources
	scriptMatches := scriptSrcRe.FindAllSubmatch(body, -1)
	for _, match := range scriptMatches {
		scriptURL := resolveURL(c.cfg.URL, string(match[1]))
		jsPaths, err := c.extractPathsFromJS(ctx, scriptURL)
		if err != nil {
			slog.Debug("failed to fetch JS", "url", scriptURL, "error", err)
			continue
		}
		for _, path := range jsPaths {
			endpoints = append(endpoints, Endpoint{
				Method:  "GET",
				Path:    path,
				FullURL: baseURL + path,
				Params:  extractPathParams(path),
			})
		}
	}

	slog.Info("endpoints from JS discovery", "count", len(endpoints))
	return endpoints, nil
}

// extractPathsFromJS downloads a JS file and extracts API path patterns.
func (c *Crawler) extractPathsFromJS(ctx context.Context, jsURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JS request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JS %s: %w", jsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading JS body: %w", err)
	}

	var paths []string
	for _, match := range apiPathRe.FindAllSubmatch(body, -1) {
		paths = append(paths, string(match[1]))
	}
	return paths, nil
}

// fromBruteForce tries common API paths against the target and returns those that respond.
func (c *Crawler) fromBruteForce(ctx context.Context) ([]Endpoint, error) {
	baseURL := strings.TrimRight(c.cfg.URL, "/")
	var endpoints []Endpoint

	for _, path := range CommonPaths {
		select {
		case <-ctx.Done():
			return endpoints, ctx.Err()
		default:
		}

		fullURL := baseURL + path
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}
		if c.cfg.Auth != nil {
			req.Header.Set(c.cfg.Auth.Header, c.cfg.Auth.Value)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 404 {
			endpoints = append(endpoints, Endpoint{
				Method:  "GET",
				Path:    path,
				FullURL: fullURL,
			})
		}

		if c.cfg.DelayMs > 0 {
			time.Sleep(time.Duration(c.cfg.DelayMs) * time.Millisecond)
		}
	}

	slog.Info("endpoints from brute-force", "count", len(endpoints))
	return endpoints, nil
}

// deduplicate removes duplicate endpoints by Method+Path key.
func (c *Crawler) deduplicate(endpoints []Endpoint) []Endpoint {
	var result []Endpoint
	for _, ep := range endpoints {
		key := ep.Method + " " + ep.Path
		if !c.seen[key] {
			c.seen[key] = true
			result = append(result, ep)
		}
	}
	return result
}

// extractPathParams returns parameter names from a path template like /users/{id}.
func extractPathParams(path string) []string {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(path, -1)
	var params []string
	for _, m := range matches {
		params = append(params, m[1])
	}
	return params
}

// extractParamsList reads an OpenAPI/Swagger `parameters` array (raw decoded
// YAML/JSON) and returns the names of params with `in: query` or `in: path`.
// Body and header params are intentionally skipped here — body probing is
// scoped to TASK-086 in Phase 11. Returns nil if the input isn't a list.
//
// Accepts the value type produced by yaml.v3 (map[string]interface{} entries)
// and the type produced by encoding/json (also map[string]interface{}). Both
// land in the same shape after Unmarshal into map[string]interface{}.
func extractParamsList(raw interface{}) []string {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var names []string
	for _, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		// $ref-only entries are common in real specs — skip them rather than
		// resolve, since spec deref is out of scope for v0.2 (TASK-086 covers).
		if _, hasRef := entry["$ref"]; hasRef {
			continue
		}
		name, _ := entry["name"].(string)
		in, _ := entry["in"].(string)
		if name == "" {
			continue
		}
		switch strings.ToLower(in) {
		case "query", "path":
			names = append(names, name)
		}
	}
	return names
}

// mergeParams combines multiple param-name lists, preserving first-seen order
// and deduplicating case-sensitively. Used to layer URL-template params,
// path-level spec params, and operation-level spec params into one list.
func mergeParams(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range lists {
		for _, name := range l {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// resolveURL resolves a potentially relative URL against a base URL.
func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}

	return baseURL.ResolveReference(refURL).String()
}
