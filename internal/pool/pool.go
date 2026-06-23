// Package pool provides a bounded worker pool with backpressure for
// per-image-redaction jobs. At most N jobs run concurrently (a global
// semaphore), so peak image-buffer memory is bounded by N times the per-part
// size cap. When the pool is saturated a job blocks up to a timeout and then
// is rejected (the caller returns 503) rather than growing goroutines without
// bound. The pool is context-aware (a client disconnect cancels the wait) and
// supports graceful shutdown via Drain.
package pool

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBackpressure is returned by Acquire when no slot becomes free within the
// acquire timeout while the pool is saturated. The caller maps it to HTTP 503.
var ErrBackpressure = errors.New("pool: saturated, backpressure timeout")

// ErrDraining is returned by Acquire after Drain/Close has begun: the pool no
// longer accepts new jobs.
var ErrDraining = errors.New("pool: draining, not accepting new jobs")

// Pool bounds concurrent jobs to a fixed size N. Acquire a slot before doing
// work and Release it (via the returned function) when done.
type Pool struct {
	sem            chan struct{}
	acquireTimeout time.Duration

	mu       sync.Mutex
	closed   bool
	inflight int
	maxSeen  int
	done     chan struct{} // closed when inflight reaches 0 after closing
}

// New returns a Pool allowing size concurrent jobs. acquireTimeout bounds how
// long Acquire blocks when saturated before returning ErrBackpressure; a
// non-positive timeout means wait indefinitely (subject to context). size must
// be >= 1.
func New(size int, acquireTimeout time.Duration) *Pool {
	if size < 1 {
		size = 1
	}
	return &Pool{
		sem:            make(chan struct{}, size),
		acquireTimeout: acquireTimeout,
		done:           make(chan struct{}),
	}
}

// Size returns the configured maximum concurrency.
func (p *Pool) Size() int { return cap(p.sem) }

// Acquire blocks until a job slot is free, the context is canceled, the
// acquire timeout elapses (ErrBackpressure), or the pool is draining
// (ErrDraining). On success it returns a release function that MUST be called
// exactly once when the job finishes.
func (p *Pool) Acquire(ctx context.Context) (release func(), err error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrDraining
	}
	p.mu.Unlock()

	var timeout <-chan time.Time
	if p.acquireTimeout > 0 {
		t := time.NewTimer(p.acquireTimeout)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case p.sem <- struct{}{}:
		// Got a slot; record in-flight bookkeeping.
		p.mu.Lock()
		if p.closed {
			// Raced with Drain: give the slot back and refuse.
			p.mu.Unlock()
			<-p.sem
			return nil, ErrDraining
		}
		p.inflight++
		if p.inflight > p.maxSeen {
			p.maxSeen = p.inflight
		}
		p.mu.Unlock()
		var once sync.Once
		return func() { once.Do(p.release) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeout:
		return nil, ErrBackpressure
	}
}

func (p *Pool) release() {
	// Decrement the in-flight counter BEFORE returning the slot to the
	// semaphore. If the slot were freed first, a waiting Acquire could grab it
	// and increment inflight before this decrement ran, making inflight (and
	// thus maxSeen) transiently overshoot N even though true concurrency never
	// exceeds N. Decrementing under the lock first keeps inflight an accurate
	// upper bound on concurrent holders.
	p.mu.Lock()
	p.inflight--
	if p.closed && p.inflight == 0 {
		select {
		case <-p.done:
			// already closed
		default:
			close(p.done)
		}
	}
	p.mu.Unlock()
	<-p.sem
}

// InFlight returns the current number of acquired-but-not-released slots. Used
// by tests to assert concurrency never exceeds Size.
func (p *Pool) InFlight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inflight
}

// MaxInFlight returns the peak concurrency observed. Used by tests to assert
// the bound was respected.
func (p *Pool) MaxInFlight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxSeen
}

// Drain stops accepting new jobs (subsequent Acquire returns ErrDraining) and
// waits for all in-flight jobs to finish or for ctx to expire. It returns
// ctx.Err() if the deadline is hit before in-flight jobs complete, otherwise
// nil. Drain is idempotent. The gateway calls Drain BEFORE http.Server.Shutdown
// so in-flight redactions complete (or the deadline forces a clean stop).
func (p *Pool) Drain(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		if p.inflight == 0 {
			select {
			case <-p.done:
			default:
				close(p.done)
			}
		}
	}
	done := p.done
	p.mu.Unlock()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
