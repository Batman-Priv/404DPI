package dpiproxy

import "sync"

type StrategyRecord struct {
	mu        sync.Mutex
	strategy  FragmentStrategy
	attempts  int64
	successes int64
}

type strategyRecordJSON struct {
	Strategy  FragmentStrategy
	Attempts  int64
	Successes int64
}

func newStrategyRecord(strat FragmentStrategy) *StrategyRecord {
	return &StrategyRecord{strategy: strat}
}

func recordFromJSON(j strategyRecordJSON) *StrategyRecord {
	return &StrategyRecord{strategy: j.Strategy, attempts: j.Attempts, successes: j.Successes}
}

func (r *StrategyRecord) snapshot() strategyRecordJSON {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strategyRecordJSON{Strategy: r.strategy, Attempts: r.attempts, Successes: r.successes}
}

func (r *StrategyRecord) current() FragmentStrategy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.strategy
}

func (r *StrategyRecord) Confidence() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempts == 0 {
		return 0
	}
	return float64(r.successes) / float64(r.attempts)
}

func (r *StrategyRecord) record(strat FragmentStrategy, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if success {
		if r.strategy.Name != strat.Name {
			r.strategy = strat
			r.attempts, r.successes = 0, 0
		}
		r.attempts++
		r.successes++
		return
	}
	if r.strategy.Name == strat.Name {
		r.attempts++
	}
}

const (
	confidenceHigh = 0.90
	confidenceLow  = 0.50
)

func looksLikeHandshake(peek []byte) bool {
	if len(peek) == 0 {
		return false
	}
	return peek[0] == 0x16
}
