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
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/redis/go-redis/v9"
)

// reconnectCount tracks how many times we've fallen back to a one-shot
// client because the cached client was closed mid-operation. Exposed via
// log lines and ReconnectCount() for ops visibility.
var reconnectCount atomic.Int64

// ReconnectCount returns the number of one-shot reconnects that have
// occurred since the process started. Useful for metrics or smoke tests.
func ReconnectCount() int64 {
	return reconnectCount.Load()
}

// errIsClientClosed reports whether err is the "redis: client is closed"
// failure that surfaces when this RedisStorage instance was Cleanup'd
// (typically by a Caddy config reload) but a caller still holds a
// reference to it for an in-flight operation — most often certmagic
// during ACME HTTP-01 issuance.
//
// go-redis/v9 does not export the sentinel (it lives in the internal
// pool package), so we string-match defensively. The error wording has
// been stable across go-redis v8 and v9.
func errIsClientClosed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "client is closed")
}

// withReconnectOnClosed runs op against rs.client. If op returns
// "client is closed" it builds a one-shot redis.UniversalClient from
// the storage's existing config, runs op once more against it, and
// closes the one-shot via defer.
//
// The fresh client is intentionally NOT cached on rs. Caddy will not
// call Cleanup again on this orphaned storage instance, so caching the
// reopen would leak the client's reaper goroutine for the lifetime of
// the process. Re-dialing per failed op trades a small handshake cost
// (only paid on the rare orphan path) for zero leaked state.
//
// Bounded to a single retry. If reconnect itself fails, the original
// op error is returned wrapped together with the reconnect failure so
// callers can see both.
func (rs RedisStorage) withReconnectOnClosed(ctx context.Context, op func(redis.UniversalClient) error) error {
	err := op(rs.client)
	if !errIsClientClosed(err) {
		return err
	}

	fresh, ferr := rs.buildClient(ctx)
	if ferr != nil {
		return fmt.Errorf("redis storage: reconnect after closed client failed: %v (original op error: %v)", ferr, err)
	}
	defer fresh.Close()

	n := reconnectCount.Add(1)
	if rs.logger != nil {
		rs.logger.Warnw("redis storage one-shot reconnect (orphaned by Caddy reload)",
			"total_reconnects_since_start", n)
	}

	return op(fresh)
}
