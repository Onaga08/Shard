package stats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"shard/internal/attack"
)

// PhaseNames for consistent iteration
var PhaseNames = []string{"dns", "connect", "tls", "ttfb", "total"}

type phaseStats struct {
	Count int
	Sum   float64
	Min   float64
	Max   float64
}

type Aggregator struct {
	count        int
	status       map[int]int
	errors       map[string]int
	stats        map[string]*phaseStats
	failByPhase  map[string]int
	statusFamily map[string]int
}

func New() *Aggregator {
	a := &Aggregator{
		status:       make(map[int]int),
		errors:       make(map[string]int),
		stats:        make(map[string]*phaseStats),
		failByPhase:  make(map[string]int),
		statusFamily: make(map[string]int),
	}
	for _, p := range PhaseNames {
		a.stats[p] = &phaseStats{Min: 1e9} // initialize with large min
	}
	return a
}

func (a *Aggregator) Add(r attack.Result) {
	a.count++

	// --- handle status code ---
	if r.Code > 0 {
		a.status[r.Code]++
		fam := r.Code / 100
		if fam >= 2 && fam <= 5 {
			key := fmt.Sprintf("%dxx", fam)
			a.statusFamily[key]++
		}
	}

	// --- handle errors and failure phase ---
	if r.Error != "" {
		a.errors[r.Error]++
	}
	if r.FailPhase != "" {
		a.failByPhase[r.FailPhase]++
	}

	// --- handle timings ---
	update := func(phase string, d time.Duration) {
		ms := float64(d.Milliseconds())
		ps := a.stats[phase]
		ps.Count++
		ps.Sum += ms
		if ms < ps.Min {
			ps.Min = ms
		}
		if ms > ps.Max {
			ps.Max = ms
		}
	}
	update("dns", r.Phases.DNS)
	update("connect", r.Phases.Connect)
	update("tls", r.Phases.TLS)
	update("ttfb", r.Phases.TTFB)
	update("total", r.Phases.Total)
}

func (a *Aggregator) LoadJSONL(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var res attack.Result
			if e := json.Unmarshal(line, &res); e == nil {
				a.Add(res)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Report prints raw math statistics per phase
func (a *Aggregator) Report(w io.Writer) {
	fmt.Fprintf(w, "\n=== Summary (%d requests) ===\n", a.count)

	fmt.Fprintln(w, "\nStatus families:")
	// print in order 2xx..5xx if present
	for _, fam := range []string{"2xx", "3xx", "4xx", "5xx"} {
		if v, ok := a.statusFamily[fam]; ok {
			fmt.Fprintf(w, "  %-3s : %d\n", fam, v)
		}
	}

	fmt.Fprintln(w, "\nStatus codes:")
	for _, code := range sortedKeysInt(a.status) {
		fmt.Fprintf(w, "  %3d : %d\n", code, a.status[code])
	}

	fmt.Fprintln(w, "\nErrors:")
	for _, key := range sortedKeysStr(a.errors) {
		fmt.Fprintf(w, "  %-10s : %d\n", key, a.errors[key])
	}
	if len(a.errors) == 0 {
		fmt.Fprintln(w, "  none")
	}

	fmt.Fprintln(w, "\nFailures by phase:")
	for _, key := range sortedKeysStr(a.failByPhase) {
		fmt.Fprintf(w, "  %-10s : %d\n", key, a.failByPhase[key])
	}
	if len(a.failByPhase) == 0 {
		fmt.Fprintln(w, "  none")
	}

	fmt.Fprintln(w, "\nPhase timings (ms):")
	fmt.Fprintf(w, "  %-8s %-10s %-10s %-10s %-10s\n", "Phase", "Avg", "Min", "Max", "Total")
	for _, name := range PhaseNames {
		s := a.stats[name]
		if s.Count == 0 {
			continue
		}
		avg := s.Sum / float64(s.Count)
		fmt.Fprintf(w, "  %-8s %-10.2f %-10.2f %-10.2f %-10.2f\n",
			name, avg, s.Min, s.Max, s.Sum)
	}
}

// helpers
func sortedKeysInt(m map[int]int) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func sortedKeysStr(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
