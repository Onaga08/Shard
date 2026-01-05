package attack

import "time"

type PhaseTimings struct {
	DNS     time.Duration `json:"dns"`
	Connect time.Duration `json:"connect"`
	TLS     time.Duration `json:"tls"`
	TTFB    time.Duration `json:"ttfb"`
	Total   time.Duration `json:"total"`
}
type Result struct {
	Timestamp time.Time    `json:"ts"`
	Code      int          `json:"code"`
	Error     string       `json:"error,omitempty"`
	FailPhase string       `json:"fail_phase,omitempty"`
	Reused    bool         `json:"reused"`
	Phases    PhaseTimings `json:"phases"`
}
