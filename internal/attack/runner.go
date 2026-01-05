package attack

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"

	"shard/internal/config"
)

// Runner executes the attack.
type Runner struct {
	cfg    *config.Config
	client *http.Client
}

// NewRunner creates a new attack runner from config.
func NewRunner(cfg *config.Config) (*Runner, error) {
	timeout, _ := time.ParseDuration(cfg.Load.Timeout)

	transport := &http.Transport{
		DisableKeepAlives: cfg.Load.DisableKeepAlive,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: cfg.Load.InsecureTLS}, // ok for testing
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &Runner{cfg: cfg, client: client}, nil
}

// Run executes the full test and writes JSONL results.
func (r *Runner) Run(ctx context.Context, outPath string) error {
	rate := r.cfg.Load.Rate
	duration, _ := time.ParseDuration(r.cfg.Load.Duration)
	concurrency := r.cfg.Load.Concurrency

	req, err := r.makeRequest()
	if err != nil {
		return fmt.Errorf("make request: %w", err)
	}

	workCh := make(chan int)
	results := make(chan Result, concurrency*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range workCh {
				res := r.doRequest(req)
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}

	// Writer goroutine
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer outFile.Close()

	go func() {
		enc := json.NewEncoder(outFile)
		for res := range results {
			_ = enc.Encode(res)
		}
	}()

	// Fixed-rate scheduler
	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	stop := time.After(duration)
	count := 0
loop:
	for {
		select {
		case <-stop:
			break loop
		case <-ticker.C:
			select {
			case workCh <- count:
				count++
			case <-ctx.Done():
				break loop
			}
		}
	}
	close(workCh)
	wg.Wait()
	close(results)
	return nil
}

// makeRequest builds the base HTTP request from config.
func (r *Runner) makeRequest() (*http.Request, error) {
	body := strings.NewReader("")
	if r.cfg.Target.BodyFile != "" {
		data, err := os.ReadFile(r.cfg.Target.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("read body file: %w", err)
		}
		body = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(r.cfg.Target.Method, r.cfg.Target.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.cfg.Target.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// doRequest executes one traced HTTP request.
func (r *Runner) doRequest(base *http.Request) Result {
	var res Result
	var phases PhaseTimings
	var reused bool

	start := time.Now()
	req := base.Clone(context.Background())

	trace := &httptrace.ClientTrace{
		GotConn:      func(info httptrace.GotConnInfo) { reused = info.Reused },
		DNSStart:     func(_ httptrace.DNSStartInfo) { phases.DNS = time.Since(start) },
		DNSDone:      func(_ httptrace.DNSDoneInfo) { phases.DNS = time.Since(start) - phases.DNS },
		ConnectStart: func(_, _ string) { phases.Connect = time.Since(start) },
		ConnectDone: func(net, addr string, err error) {
			if err == nil {
				phases.Connect = time.Since(start) - phases.Connect
			}
		},
		TLSHandshakeStart:    func() { phases.TLS = time.Since(start) },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { phases.TLS = time.Since(start) - phases.TLS },
		GotFirstResponseByte: func() { phases.TTFB = time.Since(start) },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := r.client.Do(req)
	total := time.Since(start)
	res.Timestamp = start
	res.Phases = phases
	res.Reused = reused
	res.Phases.Total = total

	if err != nil {
		res.Error = classifyError(err)
		return res
	}
	res.Code = resp.StatusCode
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return res
}

// classifyError creates a taxonomy label for an error.
func classifyError(err error) string {
	if os.IsTimeout(err) {
		return "timeout"
	}
	switch {
	case strings.Contains(err.Error(), "no such host"):
		return "dns"
	case strings.Contains(err.Error(), "connection refused"):
		return "connect"
	case strings.Contains(err.Error(), "tls"):
		return "tls"
	default:
		return "other"
	}
}
