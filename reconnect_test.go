// Copyright 2024 Pieter Berkel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storageredis

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReconnect_StoreAfterClose simulates a Caddy reload that has Cleanup'd
// the storage instance while a caller (e.g. certmagic mid-issuance) still
// holds a reference to it. Without the reconnect wrapper, the next op
// returns "redis: client is closed" and bubbles up; with the wrapper, a
// one-shot client is opened, the op succeeds, and the one-shot is closed.
func TestReconnect_StoreAfterClose(t *testing.T) {
	rs, ctx := provisionRedisStorage(t)

	// Establish baseline: storage works.
	require.NoError(t, rs.Store(ctx, TestKeyExampleCrt, TestValueCrt))

	// Simulate Caddy Cleanup mid-flight: close the cached client while
	// our (orphaned) RedisStorage reference is still alive.
	require.NoError(t, rs.client.Close())

	startReconnects := ReconnectCount()

	// This Store should detect the closed client, open a one-shot,
	// succeed, and close the one-shot. No panic, no permanent failure.
	err := rs.Store(ctx, TestKeyExampleKey, TestValueKey)
	require.NoError(t, err, "Store should self-heal after Cleanup")

	// The reconnect counter should have advanced by exactly one.
	assert.Equal(t, startReconnects+1, ReconnectCount(),
		"each closed-client retry should bump the reconnect counter once")

	// We did NOT swap rs.client; the cached client should still be closed.
	// Re-pinging confirms we're not silently caching the one-shot.
	pingErr := rs.client.Ping(ctx).Err()
	assert.True(t, isClientClosedErr(pingErr),
		"cached rs.client should remain closed; got %v", pingErr)

	// Re-provision so subsequent assertions can read what we wrote.
	require.NoError(t, rs.finalizeConfiguration(ctx))

	// Verify the value actually landed in Redis via the reconnect path.
	loaded, err := rs.Load(ctx, TestKeyExampleKey)
	require.NoError(t, err)
	assert.Equal(t, TestValueKey, loaded)
}

// TestReconnect_LoadMissingAfterClose verifies that the reconnect path
// preserves the not-found semantics expected by certmagic. A Load for a
// non-existent key after Cleanup must still return fs.ErrNotExist (not a
// client-closed error or a wrapped reconnect failure).
func TestReconnect_LoadMissingAfterClose(t *testing.T) {
	rs, ctx := provisionRedisStorage(t)

	require.NoError(t, rs.client.Close())

	_, err := rs.Load(ctx, TestKeyExampleCrt)
	assert.True(t, errors.Is(err, fs.ErrNotExist),
		"Load of missing key after Cleanup should return fs.ErrNotExist; got %v", err)
}

// TestReconnect_DeleteAfterClose covers the same path for Delete, including
// the helper-plumbed deleteDirectoryRecord call.
func TestReconnect_DeleteAfterClose(t *testing.T) {
	rs, ctx := provisionRedisStorage(t)

	require.NoError(t, rs.Store(ctx, TestKeyExampleCrt, TestValueCrt))
	require.NoError(t, rs.client.Close())

	require.NoError(t, rs.Delete(ctx, TestKeyExampleCrt))

	// Re-provision and confirm the key is gone.
	require.NoError(t, rs.finalizeConfiguration(ctx))
	exists := rs.Exists(ctx, TestKeyExampleCrt)
	assert.False(t, exists, "key should be gone after Delete via reconnect path")
}

// TestIsClientClosedErr pins the string-match sentinel so a future
// go-redis upgrade that changes the wording will fail loudly here.
func TestIsClientClosedErr(t *testing.T) {
	assert.True(t, isClientClosedErr(errors.New("redis: client is closed")))
	assert.True(t, isClientClosedErr(errors.New("operation X failed: redis: client is closed")))
	assert.False(t, isClientClosedErr(nil))
	assert.False(t, isClientClosedErr(errors.New("redis: connection refused")))
	assert.False(t, isClientClosedErr(errors.New("context canceled")))
}

// TestReconnect_ConcurrentStoresAfterClose stresses the reconnect path
// with parallel callers. Each concurrent op should independently open
// and close its own one-shot client; we tolerate any number of resulting
// reconnects (one per op or coalesced — both are correct), but they all
// must succeed and none should leak by panicking on closed pool state.
func TestReconnect_ConcurrentStoresAfterClose(t *testing.T) {
	rs, _ := provisionRedisStorage(t)

	require.NoError(t, rs.client.Close())

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("%s/concurrent-%d.bin", TestKeyExamplePath, idx)
			errs[idx] = rs.Store(context.Background(), key, TestValueCrt)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d should have stored successfully via reconnect", i)
	}
}
