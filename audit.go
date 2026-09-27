package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// ---------- input model ----------

// OpType is one of the four logged operation kinds.
type OpType string

const (
	OpRead   OpType = "READ"
	OpWrite  OpType = "WRITE"
	OpCommit OpType = "COMMIT"
	OpAbort  OpType = "ABORT"
)

// Op is a single logged operation. Seq is the 1-based position in the log,
// assigned by ParseLog (any seq present in the input is ignored). Value is
// only meaningful for WRITE (default 0).
type Op struct {
	Seq   int    `json:"seq"`
	Txn   string `json:"txn"`
	Type  OpType `json:"op"`
	Key   string `json:"key,omitempty"`
	Value int64  `json:"value,omitempty"`
}

// Log is the audited input: 2..8 transactions and up to 500 ordered ops.
type Log struct {
	Txns []string `json:"transactions"`
	Ops  []Op     `json:"ops"`
}

const (
	minTxns = 2
	maxTxns = 8
	maxOps  = 500
)

// ParseLog decodes a log from JSON and validates it:
//   - 2..8 distinct, non-empty transaction ids;
//   - 1..500 ops, each READ/WRITE/COMMIT/ABORT on a declared transaction;
//   - READ and WRITE carry a key, COMMIT and ABORT must not;
//   - every transaction has exactly one terminating COMMIT or ABORT and no
//     operation of that transaction may appear after it.
func ParseLog(data []byte) (*Log, error) {
	type rawLog struct {
		Transactions []string `json:"transactions"`
		Ops          []struct {
			Txn   *string `json:"txn"`
			Type  *OpType `json:"op"`
			Key   *string `json:"key"`
			Value int64   `json:"value"`
			Seq   int     `json:"seq"`
		} `json:"ops"`
	}

	var raw rawLog
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("invalid JSON: trailing data after log object")
	}
	if raw.Transactions == nil {
		return nil, fmt.Errorf("transactions: missing or not a JSON array")
	}
	if raw.Ops == nil {
		return nil, fmt.Errorf("ops: missing or not a JSON array")
	}
	if len(raw.Transactions) < minTxns || len(raw.Transactions) > maxTxns {
		return nil, fmt.Errorf("transactions: need %d..%d distinct ids, got %d", minTxns, maxTxns, len(raw.Transactions))
	}

	declared := make(map[string]bool, len(raw.Transactions))
	for _, t := range raw.Transactions {
		if t == "" {
			return nil, fmt.Errorf("transactions: empty id")
		}
		if declared[t] {
			return nil, fmt.Errorf("transactions: duplicate id %q", t)
		}
		declared[t] = true
	}
	if len(raw.Ops) == 0 {
		return nil, fmt.Errorf("ops: log is empty")
	}
	if len(raw.Ops) > maxOps {
		return nil, fmt.Errorf("ops: at most %d operations allowed, got %d", maxOps, len(raw.Ops))
	}

	l := &Log{Txns: raw.Transactions, Ops: make([]Op, len(raw.Ops))}
	terminated := make(map[string]OpType, len(raw.Transactions)) // txn -> its terminator type
	for i := range raw.Ops {
		r := &raw.Ops[i]
		seq := i + 1
		if r.Txn == nil || *r.Txn == "" {
			return nil, fmt.Errorf("op %d: missing transaction id", seq)
		}
		if r.Type == nil {
			return nil, fmt.Errorf("op %d: missing op type (want READ, WRITE, COMMIT or ABORT)", seq)
		}
		if !declared[*r.Txn] {
			return nil, fmt.Errorf("op %d: undeclared transaction %q", seq, *r.Txn)
		}
		if term, ok := terminated[*r.Txn]; ok {
			return nil, fmt.Errorf("op %d: transaction %q already terminated with %s", seq, *r.Txn, term)
		}

		op := Op{Seq: seq, Txn: *r.Txn, Type: *r.Type, Value: r.Value}
		switch op.Type {
		case OpRead, OpWrite:
			if r.Key == nil || *r.Key == "" {
				return nil, fmt.Errorf("op %d: %s requires a key", seq, op.Type)
			}
			op.Key = *r.Key
		case OpCommit, OpAbort:
			if r.Key != nil {
				return nil, fmt.Errorf("op %d: %s must not carry a key", seq, op.Type)
			}
			terminated[op.Txn] = op.Type
		default:
			return nil, fmt.Errorf("op %d: unknown op %q (want READ, WRITE, COMMIT or ABORT)", seq, op.Type)
		}
		l.Ops[i] = op
	}
	for _, t := range l.Txns {
		if _, ok := terminated[t]; !ok {
			return nil, fmt.Errorf("transaction %q never terminates: exactly one COMMIT or ABORT is required", t)
		}
	}
	return l, nil
}

// ---------- report model ----------

// Source describes where a READ obtained its value: the latest preceding
// WRITE on the key (even if that write was later aborted), or the initial
// version when no WRITE precedes the read.
type Source struct {
	Kind  string `json:"kind"` // "initial" or "write"
	Seq   int    `json:"seq,omitempty"`
	Txn   string `json:"txn,omitempty"`
	Value *int64 `json:"value,omitempty"`
}

// ReadFact records one READ and the source it observed.
type ReadFact struct {
	Seq    int    `json:"seq"`
	Txn    string `json:"txn"`
	Key    string `json:"key"`
	Value  *int64 `json:"value,omitempty"`
	Source Source `json:"source"`
}

// Conflict is one ordered pair of conflicting ops (same key, different
// transactions, at least one WRITE). Kind is "RW", "WR" or "WW".
type Conflict struct {
	Key     string `json:"key"`
	Kind    string `json:"kind"`
	FromSeq int    `json:"fromSeq"`
	ToSeq   int    `json:"toSeq"`
}

// Edge is a directed edge From -> To in the conflict graph, with every
// conflicting op pair that witnesses it.
type Edge struct {
	From      string     `json:"from"`
	To        string     `json:"to"`
	Conflicts []Conflict `json:"conflicts"`
}

// Violation pinpoints the first operation breaking a property.
type Violation struct {
	Seq    int    `json:"seq"`
	Txn    string `json:"txn"`
	Op     OpType `json:"op"`
	Key    string `json:"key,omitempty"`
	Reason string `json:"reason"`
}

// PropResult is the verdict for one execution property.
type PropResult struct {
	OK        bool       `json:"ok"`
	Violation *Violation `json:"violation,omitempty"`
}

// SerialResult reports conflict serializability: the lexicographically
// smallest serial order (ids compared bytewise) when the conflict graph is
// acyclic, otherwise one real directed cycle.
type SerialResult struct {
	Acyclic bool     `json:"acyclic"`
	Order   []string `json:"order,omitempty"`
	Cycle   []string `json:"cycle,omitempty"`
}

// Report is the full audit output. OK is true only when the schedule is
// conflict-serializable and satisfies all three execution properties.
type Report struct {
	OK              bool             `json:"ok"`
	Transactions    []string         `json:"transactions"`
	NumOps          int              `json:"numOps"`
	Reads           []ReadFact       `json:"reads"`
	Edges           []Edge           `json:"edges"`
	Serializability SerialResult     `json:"serializability"`
	Recoverable     PropResult       `json:"recoverable"`
	Cascadeless     PropResult       `json:"cascadeless"`
	Strict          PropResult       `json:"strict"`
	FinalState      map[string]int64 `json:"finalState"`
}

// ---------- audit ----------

// Audit scans the log once in order and derives the full report.
//
// The properties are judged purely by log position, never by the final
// state: a write becomes visible to other transactions only when its
// transaction COMMITs, and an ABORT never erases a dirty read that already
// happened.
func Audit(l *Log) *Report {
	rep := &Report{
		OK:           true,
		Transactions: l.Txns,
		NumOps:       len(l.Ops),
		FinalState:   map[string]int64{},
	}

	committed := make(map[string]int, len(l.Txns)) // txn -> commit seq
	lastWrite := make(map[string]int)              // key -> seq of latest WRITE
	readsFrom := make(map[string]map[string][]int) // reader -> writer -> read seqs
	var recV, casV, strV *Violation

	for i := range l.Ops {
		op := &l.Ops[i]
		switch op.Type {
		case OpRead:
			fact := ReadFact{Seq: op.Seq, Txn: op.Txn, Key: op.Key}
			if ws, ok := lastWrite[op.Key]; ok {
				w := &l.Ops[ws-1]
				v := w.Value
				fact.Value = &v
				fact.Source = Source{Kind: "write", Seq: w.Seq, Txn: w.Txn, Value: &v}
				if w.Txn != op.Txn {
					if readsFrom[op.Txn] == nil {
						readsFrom[op.Txn] = map[string][]int{}
					}
					readsFrom[op.Txn][w.Txn] = append(readsFrom[op.Txn][w.Txn], op.Seq)
					if _, ok := committed[w.Txn]; !ok {
						// The source write is uncommitted: its transaction is
						// still active or already aborted (an abort does not
						// cleanse the write).
						if casV == nil {
							casV = &Violation{Seq: op.Seq, Txn: op.Txn, Op: op.Type, Key: op.Key,
								Reason: fmt.Sprintf("reads uncommitted write of transaction %s (op %d)", w.Txn, w.Seq)}
						}
						if strV == nil {
							strV = &Violation{Seq: op.Seq, Txn: op.Txn, Op: op.Type, Key: op.Key,
								Reason: fmt.Sprintf("reads uncommitted write of transaction %s (op %d)", w.Txn, w.Seq)}
						}
					}
				}
			} else {
				fact.Source = Source{Kind: "initial"}
			}
			rep.Reads = append(rep.Reads, fact)
		case OpWrite:
			if ws, ok := lastWrite[op.Key]; ok {
				w := &l.Ops[ws-1]
				if w.Txn != op.Txn {
					if _, ok := committed[w.Txn]; !ok && strV == nil {
						strV = &Violation{Seq: op.Seq, Txn: op.Txn, Op: op.Type, Key: op.Key,
							Reason: fmt.Sprintf("overwrites uncommitted write of transaction %s (op %d)", w.Txn, w.Seq)}
					}
				}
			}
			lastWrite[op.Key] = op.Seq
		case OpCommit:
			// Recoverable: every transaction this one has read from must
			// already be committed. If a source aborted or is still active,
			// committing now is the first recoverability violation.
			if recV == nil {
				writers := make([]string, 0, len(readsFrom[op.Txn]))
				for wt := range readsFrom[op.Txn] {
					writers = append(writers, wt)
				}
				sort.Strings(writers)
				for _, wt := range writers {
					if _, ok := committed[wt]; !ok && recV == nil {
						recV = &Violation{Seq: op.Seq, Txn: op.Txn, Op: op.Type,
							Reason: fmt.Sprintf("commits before its source transaction %s (read at op %d) has committed", wt, readsFrom[op.Txn][wt][0])}
					}
				}
			}
			committed[op.Txn] = op.Seq
		case OpAbort:
			// Aborting is always safe for the aborting transaction itself;
			// readers of its writes are caught at their own COMMIT.
		}
	}

	rep.Edges = conflictEdges(l)
	rep.Serializability = classify(l.Txns, rep.Edges)
	rep.Recoverable = PropResult{OK: recV == nil, Violation: recV}
	rep.Cascadeless = PropResult{OK: casV == nil, Violation: casV}
	rep.Strict = PropResult{OK: strV == nil, Violation: strV}
	rep.OK = rep.Serializability.Acyclic && rep.Recoverable.OK && rep.Cascadeless.OK && rep.Strict.OK

	// Final committed state: writes of committed transactions, applied in
	// log order. Shown for contrast only — it can look perfectly correct
	// while the properties above are violated.
	for i := range l.Ops {
		op := &l.Ops[i]
		if op.Type == OpWrite {
			if _, ok := committed[op.Txn]; ok {
				rep.FinalState[op.Key] = op.Value
			}
		}
	}
	return rep
}

// conflictEdges builds the directed conflict graph: for every ordered pair
// of ops (a before b in the log) on the same key by different transactions
// where at least one is a WRITE, an edge a.Txn -> b.Txn.
func conflictEdges(l *Log) []Edge {
	type pair struct{ from, to string }
	byPair := map[pair][]Conflict{}
	for i := range l.Ops {
		a := &l.Ops[i]
		if a.Type != OpRead && a.Type != OpWrite {
			continue
		}
		for j := i + 1; j < len(l.Ops); j++ {
			b := &l.Ops[j]
			if b.Type != OpRead && b.Type != OpWrite {
				continue
			}
			if a.Txn == b.Txn || a.Key != b.Key {
				continue
			}
			if a.Type == OpRead && b.Type == OpRead {
				continue
			}
			p := pair{a.Txn, b.Txn}
			byPair[p] = append(byPair[p], Conflict{
				Key:     a.Key,
				Kind:    string(a.Type[0]) + string(b.Type[0]),
				FromSeq: a.Seq,
				ToSeq:   b.Seq,
			})
		}
	}
	edges := make([]Edge, 0, len(byPair))
	for p, cs := range byPair {
		edges = append(edges, Edge{From: p.from, To: p.to, Conflicts: cs})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	return edges
}

// classify topologically sorts the conflict graph. When it is acyclic the
// result is the lexicographically smallest serial order (transaction ids
// compared bytewise); otherwise a real directed cycle is returned.
func classify(txns []string, edges []Edge) SerialResult {
	adj := make(map[string][]string, len(txns))
	indeg := make(map[string]int, len(txns))
	for _, t := range txns {
		indeg[t] = 0
	}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
		indeg[e.To]++
	}
	for t := range adj {
		sort.Strings(adj[t])
	}

	// Kahn's algorithm, always emitting the byte-order-smallest available
	// id: this yields the lexicographically smallest topological order.
	remaining := make(map[string]bool, len(txns))
	for _, t := range txns {
		remaining[t] = true
	}
	order := make([]string, 0, len(txns))
	for len(remaining) > 0 {
		best := ""
		for t := range remaining {
			if indeg[t] == 0 && (best == "" || t < best) {
				best = t
			}
		}
		if best == "" {
			return SerialResult{Acyclic: false, Cycle: findCycle(txns, adj)}
		}
		order = append(order, best)
		delete(remaining, best)
		for _, m := range adj[best] {
			indeg[m]--
		}
	}
	return SerialResult{Acyclic: true, Order: order}
}

// findCycle returns one real directed cycle as a list of transaction ids
// with the first id repeated at the end; every consecutive pair (including
// last -> first) is an edge of the graph. Deterministic: transactions and
// adjacency lists are visited in byte order.
func findCycle(txns []string, adj map[string][]string) []string {
	const (
		white = iota
		gray
		black
	)
	color := make(map[string]int, len(txns))
	var stack []string
	var visit func(u string) []string
	visit = func(u string) []string {
		color[u] = gray
		stack = append(stack, u)
		for _, v := range adj[u] {
			switch color[v] {
			case gray:
				start := 0
				for stack[start] != v {
					start++
				}
				cycle := append([]string{}, stack[start:]...)
				return append(cycle, v)
			case white:
				if c := visit(v); c != nil {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = black
		return nil
	}
	ordered := append([]string{}, txns...)
	sort.Strings(ordered)
	for _, t := range ordered {
		if color[t] == white {
			if c := visit(t); c != nil {
				return c
			}
		}
	}
	return nil
}
