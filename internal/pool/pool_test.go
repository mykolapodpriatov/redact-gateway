package pool_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"redact-gateway/internal/pool"
)

func TestBoundedConcurrency(t *testing.T) {
	const n = 4
	p := pool.New(n, time.Second)

	var current atomic.Int32
	var peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := p.Acquire(context.Background())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			defer release()
			c := current.Add(1)
			for {
				old := peak.Load()
				if c <= old || peak.CompareAndSwap(old, c) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			current.Add(-1)
		}()
	}
	wg.Wait()

	if peak.Load() > n {
		t.Fatalf("concurrency exceeded N: peak=%d N=%d", peak.Load(), n)
	}
	if p.MaxInFlight() > n {
		t.Fatalf("pool MaxInFlight exceeded N: %d", p.MaxInFlight())
	}
	if p.InFlight() != 0 {
		t.Fatalf("slots leaked: InFlight=%d", p.InFlight())
	}
}

func TestBackpressureTimeout(t *testing.T) {
	p := pool.New(1, 20*time.Millisecond)
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	// Second acquire must time out with ErrBackpressure (the single slot is
	// held).
	_, err = p.Acquire(context.Background())
	if !errors.Is(err, pool.ErrBackpressure) {
		t.Fatalf("want ErrBackpressure, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	p := pool.New(1, time.Minute)
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_, err = p.Acquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestDrainWaitsForInflight(t *testing.T) {
	p := pool.New(2, time.Second)
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	drained := make(chan error, 1)
	go func() {
		drained <- p.Drain(context.Background())
	}()

	// Drain should not complete while the slot is held.
	select {
	case <-drained:
		t.Fatal("Drain returned before in-flight job finished")
	case <-time.After(30 * time.Millisecond):
	}

	// New acquisitions are refused during drain.
	if _, err := p.Acquire(context.Background()); !errors.Is(err, pool.ErrDraining) {
		t.Fatalf("want ErrDraining during drain, got %v", err)
	}

	release()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("drain returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain did not complete after in-flight job finished")
	}
}

func TestDrainDeadline(t *testing.T) {
	p := pool.New(1, time.Second)
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Drain(ctx); err == nil {
		t.Fatal("expected Drain to hit its deadline while a job is held")
	}
}

func TestDrainIdempotent(t *testing.T) {
	p := pool.New(2, time.Second)
	if err := p.Drain(context.Background()); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if err := p.Drain(context.Background()); err != nil {
		t.Fatalf("second drain: %v", err)
	}
}

func TestReleaseIdempotent(t *testing.T) {
	p := pool.New(1, time.Second)
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	release() // must be a no-op, not panic or double-free a slot
	// A fresh acquire should now succeed immediately.
	r2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("re-acquire after double release: %v", err)
	}
	r2()
}
