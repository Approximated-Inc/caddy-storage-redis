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

// reconnectCount tracks how many one-shot reconnects we've performed because
// the cached client was closed mid-operation. Package-level (rather than a
// field on RedisStorage) because it must outlive any single instance: the
// reconnects happen on orphaned storage structs that Caddy has already moved
// past, while a fresh RedisStorage is provisioned for new traffic. The
// counter belongs to the process so ops can see total churn.
var reconnectCount atomic.Int64

// ReconnectCount returns the number of one-shot reconnects that have
// occurred since the process started. Useful for metrics or smoke tests.
func ReconnectCount() int64 {
	return reconnectCount.Load()
}

// isClientClosedErr reports whether err is the "redis: client is closed"
// failure that surfaces when this RedisStorage instance was Cleanup'd
// (typically by a Caddy config reload) but a caller still holds a
// reference to it for an in-flight operation — most often certmagic
// during ACME HTTP-01 issuance.
//
// go-redis/v9 does export the sentinel as redis.ErrClosed, but the
// helpers in this package wrap with fmt.Errorf("...: %v", err) (e.g.
// storeDirectoryRecord) which strips the errors.Is chain, so we
// substring-match instead. TestIsClientClosedErr pins the wording so a
// future go-redis upgrade that changes it fails loudly.
func isClientClosedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "client is closed")
}

// withReconnectOnClosed runs op against rs.client. If op returns
// "client is closed" it builds a one-shot redis.UniversalClient from
// the storage's existing config, runs op once more against it, and
// closes the one-shot via defer.
//
// The fresh client is intentionally NOT cached on rs. Caddy will not
// call Cleanup again on this orphaned storage instance, and caching
// would leak resources tied to the new client. The size of the leak
// depends on the topology: for the failover (sentinel) client, a
// background pubsub-listen goroutine survives until Close; the simple
// and cluster clients hold a connection pool until Close. Re-dialing
// per failed op trades a small handshake cost (only paid on the rare
// orphan path) for zero leaked state across all topologies.
//
// Bounded to a single retry. If reconnect itself fails (e.g. Redis is
// genuinely down), the reconnect error is wrapped with %w so callers
// can errors.Is the original op error if needed; the reconnect failure
// is included as %v for diagnostics.
func (rs RedisStorage) withReconnectOnClosed(ctx context.Context, op func(redis.UniversalClient) error) error {
	err := op(rs.client)
	if !isClientClosedErr(err) {
		return err
	}

	fresh, ferr := rs.buildClient(ctx)
	if ferr != nil {
		return fmt.Errorf("redis storage: reconnect after closed client failed: %v (original op error: %w)", ferr, err)
	}
	defer fresh.Close()

	n := reconnectCount.Add(1)
	if rs.logger != nil {
		rs.logger.Warnw("redis storage one-shot reconnect (orphaned by Caddy reload)",
			"total_reconnects_since_start", n)
	}

	return op(fresh)
}
