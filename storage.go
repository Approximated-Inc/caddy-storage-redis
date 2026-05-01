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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bsm/redislock"
	"github.com/caddyserver/certmagic"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// Redis client type
	defaultClientType = "simple"

	// Redis server host
	defaultHost = "127.0.0.1"

	// Redis server port
	defaultPort = "6379"

	// Redis server database
	defaultDb = "0"

	// Prepended to every Redis key
	defaultKeyPrefix = "caddy"

	// Separator for Redis key path segments
	keyPathSeparator = "/"

	// Connect to Redis via TLS
	defaultTLS = false

	// Always verify TLS cerficate
	defaultTLSInsecure = false

	// Redis lock time-to-live
	lockTTL = 5 * time.Second

	// Delay between attempts to obtain Lock
	lockPollInterval = 1 * time.Second

	// How frequently the Lock's TTL should be updated
	lockRefreshInterval = 3 * time.Second
)

// RedisStorage implements a Caddy storage backend for Redis
// It supports Single (Standalone), Cluster, or Sentinel (Failover) Redis server configurations.
type RedisStorage struct {
	// ClientType specifies the Redis client type. Valid values are "cluster" or "failover"
	ClientType string `json:"client_type"`
	// Address The full address of the Redis server. Example: "127.0.0.1:6379"
	// If not defined, will be generated from Host and Port parameters.
	Address []string `json:"address"`
	// Host The Redis server hostname or IP address. Default: "127.0.0.1"
	Host []string `json:"host"`
	// Host The Redis server port number. Default: "6379"
	Port []string `json:"port"`
	// DB The Redis server database number. Default: 0. Supports Caddy placeholder substitution.
	DB DBIndex `json:"db"`
	// Timeout The Redis server timeout in seconds. Default: 5
	Timeout string `json:"timeout"`
	// Username The username for authenticating with the Redis server. Default: "" (No authentication)
	Username string `json:"username"`
	// Password The password for authenticating with the Redis server. Default: "" (No authentication)
	Password string `json:"password"`
	// SentinelPassword Optional The Redis sentinel password if authentication is enabled.
	SentinelPassword string `json:"sentinel_password"`
	// MasterName Only required when connecting to Redis via Sentinel (Failover mode). Default ""
	MasterName string `json:"master_name"`
	// KeyPrefix A string prefix that is appended to Redis keys. Default: "caddy"
	// Useful when the Redis server is used by multiple applications.
	KeyPrefix string `json:"key_prefix"`
	// EncryptionKey A key string used to symmetrically encrypt and decrypt data stored in Redis.
	// The key must be exactly 32 characters, longer values will be truncated. Default: "" (No encryption)
	EncryptionKey string `json:"encryption_key"`
	// Compression Specifies the compression algorithm to use when storing values in Redis.
	// Valid values are "flate", "zlib", or "false" (no compression). Default: "" (no compression)
	// Supports Caddy placeholders (e.g. {env.COMPRESSION}).
	Compression CompressionMode `json:"compression"`
	// TlsEnabled controls whether TLS will be used to connect to the Redis
	// server. False by default.
	TlsEnabled bool `json:"tls_enabled"`
	// TlsInsecure controls whether the client will verify the server
	// certificate. See `InsecureSkipVerify` in `tls.Config` for details. False
	// by default.
	// https://pkg.go.dev/crypto/tls#Config
	TlsInsecure bool `json:"tls_insecure"`
	// TlsServerCertsPEM is a series of PEM encoded certificates that will be
	// used by the client to validate trust in the Redis server's certificate
	// instead of the system trust store. May not be specified alongside
	// `TlsServerCertsPath`. See `x509.CertPool.AppendCertsFromPem` for details.
	// https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM
	TlsServerCertsPEM string `json:"tls_server_certs_pem"`
	// TlsServerCertsPath is the path to a file containing a series of PEM
	// encoded certificates that will be used by the client to validate trust in
	// the Redis server's certificate instead of the system trust store. May not
	// be specified alongside `TlsServerCertsPem`. See
	// `x509.CertPool.AppendCertsFromPem` for details.
	// https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM
	TlsServerCertsPath string `json:"tls_server_certs_path"`
	// RouteByLatency Route commands by latency, only used in Cluster mode. Default: false
	RouteByLatency bool `json:"route_by_latency"`
	// RouteRandomly Route commands randomly, only used in Cluster mode. Default: false
	RouteRandomly bool `json:"route_randomly"`

	client redis.UniversalClient
	locker *redislock.Client
	logger *zap.SugaredLogger
	locks  *sync.Map
}

// CompressionMode specifies the compression algorithm used when storing values.
// Accepts both the legacy boolean form (true=flate, false=none) and string form in JSON,
// allowing runtime placeholder substitution via Caddy's replacer (e.g. {env.COMPRESSION}).
type CompressionMode string

const (
	CompressionNone  CompressionMode = ""
	CompressionFlate CompressionMode = "flate"
	CompressionZlib  CompressionMode = "zlib"
)

// UnmarshalJSON accepts both the legacy boolean form used before v1.7.1
// ("compression": true/false) and the new string form ("compression": "flate"/"zlib"/"false"),
// preserving backwards compatibility with existing JSON configurations.
func (c *CompressionMode) UnmarshalJSON(data []byte) error {
	// Try bool first to handle legacy configs: true → "flate", false → ""
	var b bool
	if json.Unmarshal(data, &b) == nil {
		if b {
			*c = CompressionFlate
		} else {
			*c = CompressionNone
		}
		return nil
	}
	// Fall through to string form for new configs and placeholder-resolved values
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*c = CompressionMode(s)
	return nil
}

// DBIndex holds a Redis database index. It accepts both integer (legacy JSON form)
// and string (new JSON form) during unmarshalling, enabling runtime placeholder
// substitution via Caddy's replacer (e.g. {env.REDIS_DB}).
type DBIndex string

// UnmarshalJSON accepts both the legacy integer form used in earlier configs
// ("db": 0) and the new string form ("db": "0"), preserving backwards compatibility.
func (d *DBIndex) UnmarshalJSON(data []byte) error {
	// Try int first to handle legacy JSON configs
	var n int
	if json.Unmarshal(data, &n) == nil {
		*d = DBIndex(strconv.Itoa(n))
		return nil
	}
	// Fall through to string form for new configs and placeholder-resolved values
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*d = DBIndex(s)
	return nil
}

type heldLock struct {
	lock   *redislock.Lock
	cancel context.CancelFunc
}

// StorageData compression flag values stored per value in Redis.
const (
	storageCompressionNone  = 0
	storageCompressionFlate = 1
	storageCompressionZlib  = 2
)

type StorageData struct {
	Value       []byte    `json:"value"`
	Modified    time.Time `json:"modified"`
	Size        int64     `json:"size"`
	Compression int       `json:"compression"`
	Encryption  int       `json:"encryption"`
}

// create a new RedisStorage struct with default values
func New() *RedisStorage {

	rs := RedisStorage{
		ClientType:  defaultClientType,
		Host:        []string{defaultHost},
		Port:        []string{defaultPort},
		DB:          DBIndex(defaultDb),
		KeyPrefix:   defaultKeyPrefix,
		Compression: CompressionNone,
		TlsEnabled:  defaultTLS,
		TlsInsecure: defaultTLSInsecure,
	}
	return &rs
}

// Initialize Redis client and locker. The client and locker are stored on
// rs for use by the public storage methods. buildClient does the actual
// construction and is shared with withReconnectOnClosed.
func (rs *RedisStorage) initRedisClient(ctx context.Context) error {
	client, err := rs.buildClient(ctx)
	if err != nil {
		return err
	}
	rs.client = client
	rs.locker = redislock.New(rs.client)
	rs.locks = &sync.Map{}
	return nil
}

// buildClient constructs and pings a redis.UniversalClient from rs's
// current configuration without mutating rs.client. Called by:
//   - initRedisClient (assigns the result to rs.client during Provision)
//   - withReconnectOnClosed (one-shot retry path for orphaned storage)
//
// Caller is responsible for closing the returned client.
func (rs RedisStorage) buildClient(ctx context.Context) (redis.UniversalClient, error) {

	// DB was validated in finalizeConfiguration; parse is safe here
	dbInt, _ := strconv.Atoi(string(rs.DB))

	// Configure options for all client types
	clientOpts := redis.UniversalOptions{
		Addrs:      rs.Address,
		MasterName: rs.MasterName,
		Username:   rs.Username,
		Password:   rs.Password,
		DB:         dbInt,
	}

	// Configure timeout values if defined
	if rs.Timeout != "" {
		// Was already sanity-checked in UnmarshalCaddyfile
		timeout, _ := strconv.Atoi(rs.Timeout)
		clientOpts.DialTimeout = time.Duration(timeout) * time.Second
		clientOpts.ReadTimeout = time.Duration(timeout) * time.Second
		clientOpts.WriteTimeout = time.Duration(timeout) * time.Second
	}

	// Configure cluster routing options
	if rs.RouteByLatency || rs.RouteRandomly {
		clientOpts.RouteByLatency = rs.RouteByLatency
		clientOpts.RouteRandomly = rs.RouteRandomly
	}

	// Configure TLS support if enabled
	if rs.TlsEnabled {
		clientOpts.TLSConfig = &tls.Config{
			InsecureSkipVerify: rs.TlsInsecure,
		}

		if len(rs.TlsServerCertsPEM) > 0 && len(rs.TlsServerCertsPath) > 0 {
			return nil, fmt.Errorf("Cannot specify TlsServerCertsPEM alongside TlsServerCertsPath")
		}

		if len(rs.TlsServerCertsPEM) > 0 || len(rs.TlsServerCertsPath) > 0 {
			certPool := x509.NewCertPool()
			pem := []byte(rs.TlsServerCertsPEM)

			if len(rs.TlsServerCertsPath) > 0 {
				var err error
				pem, err = os.ReadFile(rs.TlsServerCertsPath)
				if err != nil {
					return nil, fmt.Errorf("Failed to load PEM server certs from file %s: %v", rs.TlsServerCertsPath, err)
				}
			}

			if !certPool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("Failed to load PEM server certs")
			}

			clientOpts.TLSConfig.RootCAs = certPool
		}
	}

	// Create appropriate Redis client type
	if rs.ClientType == "failover" && clientOpts.MasterName == "" {
		return nil, fmt.Errorf("'master_name' is required when using 'failover' client type")
	}

	if rs.ClientType == "failover" {

		if rs.SentinelPassword != "" {
			clientOpts.SentinelPassword = rs.SentinelPassword
		}

		// Create new Redis Failover Cluster client
		clusterClient := redis.NewFailoverClusterClient(clientOpts.Failover())

		// Test connection to the Redis cluster
		err := clusterClient.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
			return shard.Ping(ctx).Err()
		})
		if err != nil {
			clusterClient.Close()
			return nil, err
		}
		return clusterClient, nil

	} else if rs.ClientType == "cluster" || len(clientOpts.Addrs) > 1 {

		// Create new Redis Cluster client
		clusterClient := redis.NewClusterClient(clientOpts.Cluster())

		// Test connection to the Redis cluster
		err := clusterClient.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
			return shard.Ping(ctx).Err()
		})
		if err != nil {
			clusterClient.Close()
			return nil, err
		}
		return clusterClient, nil
	}

	// Create new Redis simple standalone client
	client := redis.NewClient(clientOpts.Simple())

	// Test connection to the Redis server
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func (rs RedisStorage) Store(ctx context.Context, key string, value []byte) error {

	var size = len(value)
	var compressionFlag = storageCompressionNone
	var encryptionFlag = 0

	// Compress value if compression enabled
	if rs.Compression != CompressionNone {
		compressedValue, err := rs.compress(value)
		if err != nil {
			return fmt.Errorf("Unable to compress value for %s: %v", key, err)
		}
		// Check compression efficiency
		if size > len(compressedValue) {
			value = compressedValue
			if rs.Compression == CompressionZlib {
				compressionFlag = storageCompressionZlib
			} else {
				compressionFlag = storageCompressionFlate
			}
		}
	}

	// Encrypt value if encryption enabled
	if rs.EncryptionKey != "" {
		encryptedValue, err := rs.encrypt(value)
		if err != nil {
			return fmt.Errorf("Unable to encrypt value for %s: %v", key, err)
		}
		value = encryptedValue
		encryptionFlag = 1
	}

	sd := &StorageData{
		Value:       value,
		Modified:    time.Now(),
		Size:        int64(size),
		Compression: compressionFlag,
		Encryption:  encryptionFlag,
	}

	jsonValue, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("Unable to marshal value for %s: %v", key, err)
	}

	var prefixedKey = rs.prefixKey(key)
	score := float64(sd.Modified.Unix())

	return rs.withReconnectOnClosed(ctx, func(client redis.UniversalClient) error {
		// Create directory structure set for current key
		if err := rs.storeDirectoryRecord(ctx, client, prefixedKey, score, false, false); err != nil {
			return fmt.Errorf("Unable to create directory for key %s: %v", key, err)
		}

		// Store the key value in the Redis database
		if err := client.Set(ctx, prefixedKey, jsonValue, 0).Err(); err != nil {
			return fmt.Errorf("Unable to set value for %s: %v", key, err)
		}

		return nil
	})
}

func (rs RedisStorage) Load(ctx context.Context, key string) ([]byte, error) {

	var sd *StorageData

	err := rs.withReconnectOnClosed(ctx, func(client redis.UniversalClient) error {
		var loadErr error
		sd, loadErr = rs.loadStorageData(ctx, client, key)
		return loadErr
	})
	if err != nil {
		return nil, err
	}
	value := sd.Value

	// Decrypt value if encrypted
	if sd.Encryption > 0 {
		var decErr error
		value, decErr = rs.decrypt(value)
		if decErr != nil {
			return nil, fmt.Errorf("Unable to decrypt value for %s: %v", key, decErr)
		}
	}

	// Decompress value if compressed
	if sd.Compression > storageCompressionNone {
		var decErr error
		value, decErr = rs.decompress(value, sd.Compression)
		if decErr != nil {
			return nil, fmt.Errorf("Unable to decompress value for %s: %v", key, decErr)
		}
	}

	return value, nil
}

func (rs RedisStorage) Delete(ctx context.Context, key string) error {

	var prefixedKey = rs.prefixKey(key)

	return rs.withReconnectOnClosed(ctx, func(client redis.UniversalClient) error {
		// Remove current key from directory structure
		if err := rs.deleteDirectoryRecord(ctx, client, prefixedKey, false); err != nil {
			return fmt.Errorf("Unable to delete directory for key %s: %v", key, err)
		}

		if err := client.Del(ctx, prefixedKey).Err(); err != nil {
			return fmt.Errorf("Unable to delete key %s: %v", key, err)
		}

		return nil
	})
}

func (rs RedisStorage) Exists(ctx context.Context, key string) bool {
	var exists bool
	err := rs.withReconnectOnClosed(ctx, func(client redis.UniversalClient) error {
		var existsErr error
		exists, existsErr = rs.existsKey(ctx, client, key)
		return existsErr
	})
	if err != nil {
		// CertMagic interface requires a boolean return only.
		if rs.logger != nil {
			rs.logger.Warnw("Exists check failed", "key", key, "error", err)
		}
		return false
	}
	return exists
}

// existsKey checks whether the user-facing key exists in Redis under
// the configured key prefix. The client argument is the active client
// (rs.client on the happy path, a one-shot during reconnect retries).
func (rs RedisStorage) existsKey(ctx context.Context, client redis.UniversalClient, key string) (bool, error) {
	// Redis returns a count of the number of keys found
	exists, err := rs.existsRawKey(ctx, client, rs.prefixKey(key))
	if err != nil {
		return false, fmt.Errorf("Unable to check existence for %s: %v", key, err)
	}
	return exists, nil
}

// existsRawKey checks whether a fully-qualified Redis key (no prefix
// applied) currently exists. The client argument is threaded through so
// a single op stays on one client (cached or one-shot).
func (rs RedisStorage) existsRawKey(ctx context.Context, client redis.UniversalClient, redisKey string) (bool, error) {
	existsCount, err := client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}
	return existsCount > 0, nil
}

func (rs RedisStorage) List(ctx context.Context, dir string, recursive bool) ([]string, error) {

	var keyList []string
	var currKey = rs.prefixKey(dir)

	var keys []string
	if err := rs.withReconnectOnClosed(ctx, func(client redis.UniversalClient) error {
		// Obtain range of all direct children stored in the Sorted Set
		var rangeErr error
		keys, rangeErr = client.ZRange(ctx, currKey, 0, -1).Result()
		if rangeErr != nil {
			return fmt.Errorf("Unable to get range on sorted set '%s': %v", currKey, rangeErr)
		}
		return nil
	}); err != nil {
		return keyList, err
	}

	// Iterate over each child key
	for _, k := range keys {
		// Directory keys will have a "/" suffix
		trimmedKey := strings.TrimSuffix(k, keyPathSeparator)
		// Reconstruct the full path of child key
		fullPathKey := path.Join(dir, trimmedKey)
		// If current key is a directory
		if recursive && k != trimmedKey {
			// Recursively traverse all child directories
			childKeys, err := rs.List(ctx, fullPathKey, recursive)
			if err != nil {
				return keyList, err
			}
			keyList = append(keyList, childKeys...)
		} else {
			keyList = append(keyList, fullPathKey)
		}
	}

	return keyList, nil
}

func (rs RedisStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {

	var sd *StorageData
	err := rs.withReconnectOnClosed(ctx, func(client redis.UniversalClient) error {
		var loadErr error
		sd, loadErr = rs.loadStorageData(ctx, client, key)
		return loadErr
	})
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   sd.Modified,
		Size:       sd.Size,
		IsTerminal: true,
	}, nil
}

// Lock and Unlock are intentionally NOT wrapped with withReconnectOnClosed.
// rs.locker wraps a redislock.Client around rs.client, so a one-shot retry
// would also need a fresh redislock.Client and would not match the existing
// rs.locks bookkeeping. The orphaned-storage case is recovered at a higher
// level: when Caddy reloads, the new TLS app re-dispatches issuance via
// ManageAsync against the freshly Provisioned RedisStorage, bypassing the
// orphan entirely. (Note: certmagic's acquireLock does NOT itself retry on
// storage errors, so the self-heal genuinely depends on Caddy's reload
// re-dispatch — not a hidden certmagic retry.) If logs show recurring
// redislock failures during reloads, revisit this and wrap both ops.
func (rs *RedisStorage) Lock(ctx context.Context, name string) error {

	key := rs.prefixLock(name)

	for {
		// try to obtain lock
		lock, err := rs.locker.Obtain(ctx, key, lockTTL, &redislock.Options{})

		// lock successfully obtained
		if err == nil {
			refreshCtx, cancel := context.WithCancel(context.Background())
			// store lock handle + refresh cancel function for Unlock()
			rs.locks.Store(key, heldLock{
				lock:   lock,
				cancel: cancel,
			})
			// keep the lock fresh until Unlock() cancels refreshCtx
			go func(ctx context.Context, lock *redislock.Lock) {
				ticker := time.NewTicker(lockRefreshInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
					case <-ctx.Done():
						return
					}

					// refresh the Redis lock
					err := lock.Refresh(ctx, lockTTL, nil)
					if err == redislock.ErrNotObtained {
						// lock was lost (expired or released externally), stop refreshing
						return
					}
					if isClientClosedErr(err) {
						// Cached client was closed by Caddy reload (Cleanup).
						// The new storage instance will own future refreshes;
						// keep looping here only produces 3s-cadence log noise
						// until Unlock fires its cancel. Exit so the orphan
						// goroutine reaps cleanly.
						return
					}
					if err != nil && rs.logger != nil {
						rs.logger.Warnw("Failed to refresh lock, will retry", "key", key, "error", err)
					}
				}
			}(refreshCtx, lock)

			return nil
		}

		// check for unexpected error
		if err != redislock.ErrNotObtained {
			return fmt.Errorf("Unable to obtain lock for %s: %v", key, err)
		}

		// lock already exists, wait and try again until cancelled
		select {
		case <-time.After(lockPollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (rs *RedisStorage) Unlock(ctx context.Context, name string) error {

	key := rs.prefixLock(name)

	// load and delete lock from sync.Map
	if syncMapLock, loaded := rs.locks.LoadAndDelete(key); loaded {

		// type assertion for held lock
		if lock, ok := syncMapLock.(heldLock); ok {
			lock.cancel()

			// release the Redis lock
			if err := lock.lock.Release(ctx); err != nil {
				return fmt.Errorf("Unable to release lock for %s: %v", key, err)
			}
		}
	}

	return nil
}

// Repair is intentionally NOT wrapped with withReconnectOnClosed. It's
// admin-only (invoked via the `caddy storage-redis-repair` CLI), holds
// rs.client across many Redis ops in a long loop, and isn't on certmagic's
// cert-issuance path — so a Caddy reload during a Repair is rare enough
// that the overhead of one-shot retries per op outweighs the benefit. If
// Repair fails on a closed client, the operator can simply rerun it.
func (rs *RedisStorage) Repair(ctx context.Context, dir string) error {

	var currKey = rs.prefixKey(dir)

	// Perform recursive full key scan only from the root directory
	if dir == "" {

		var pointer uint64 = 0
		var scanCount int64 = 500

		for {
			// Scan for keys matching the search query and iterate until all found
			keys, nextPointer, err := rs.client.Scan(ctx, pointer, currKey+"*", scanCount).Result()
			if err != nil {
				return fmt.Errorf("Unable to scan path %s: %v", currKey, err)
			}

			// Iterate over returned keys
			for _, key := range keys {
				// Proceed only if key type is regular string value
				keyType := rs.client.Type(ctx, key).Val()
				if keyType != "string" {
					continue
				}

				// Load the Storage Data struct to obtain modified time
				trimmedKey := rs.trimKey(key)
				sd, err := rs.loadStorageData(ctx, rs.client, trimmedKey)
				if err != nil {
					if rs.logger != nil {
						rs.logger.Infof("Unable to load storage data for key '%s'", trimmedKey)
					}
					continue
				}

				// Repair directory structure set for current key
				score := float64(sd.Modified.Unix())
				if err := rs.storeDirectoryRecord(ctx, rs.client, key, score, true, false); err != nil {
					return fmt.Errorf("Unable to repair directory index for key '%s'", trimmedKey)
				}
			}

			// End of results reached
			if nextPointer == 0 {
				break
			}
			pointer = nextPointer
		}
	}

	// Obtain range of all direct children stored in the Sorted Set
	keys, err := rs.client.ZRange(ctx, currKey, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("Unable to get range on sorted set '%s': %v", currKey, err)
	}

	// Iterate over each child key
	for _, k := range keys {
		// Directory keys will have a "/" suffix
		trimmedKey := strings.TrimSuffix(k, keyPathSeparator)

		// Reconstruct the full path of child key
		fullPathKey := path.Join(dir, trimmedKey)

		// Remove key from set if it does not exist
		exists, err := rs.existsKey(ctx, rs.client, fullPathKey)
		if err != nil {
			return err
		}
		if !exists {
			if err := rs.client.ZRem(ctx, currKey, k).Err(); err != nil {
				return fmt.Errorf("Unable to remove stale record '%s' from directory '%s': %v", k, currKey, err)
			}
			if rs.logger != nil {
				rs.logger.Infof("Removed non-existent record '%s' from directory '%s'", k, currKey)
			}
			continue
		}

		// If current key is a directory
		if k != trimmedKey {
			// Recursively traverse all child directories
			if err := rs.Repair(ctx, fullPathKey); err != nil {
				return err
			}
		}
	}

	return nil
}

func (rs *RedisStorage) trimKey(key string) string {
	return strings.TrimPrefix(strings.TrimPrefix(key, rs.KeyPrefix), keyPathSeparator)
}

func (rs *RedisStorage) prefixKey(key string) string {
	return path.Join(rs.KeyPrefix, key)
}

func (rs *RedisStorage) prefixLock(key string) string {
	return rs.prefixKey(path.Join("locks", key))
}

// loadStorageData reads and JSON-decodes the StorageData blob for key.
// The client argument is the active client (rs.client on the happy path,
// a one-shot during reconnect retries) so callers can route through
// withReconnectOnClosed.
func (rs RedisStorage) loadStorageData(ctx context.Context, client redis.UniversalClient, key string) (*StorageData, error) {

	data, err := client.Get(ctx, rs.prefixKey(key)).Bytes()
	if data == nil || errors.Is(err, redis.Nil) {
		return nil, fs.ErrNotExist
	} else if err != nil {
		return nil, fmt.Errorf("Unable to get data for %s: %v", key, err)
	}

	sd := &StorageData{}
	if err := json.Unmarshal(data, sd); err != nil {
		return nil, fmt.Errorf("Unable to unmarshal value for %s: %v", key, err)
	}

	return sd, nil
}

// Store directory index in Redis ZSet structure for fast and efficient traversal in List().
// Recurses against the same client argument so a single op stays on one client (cached or
// one-shot) for its full lifetime — important during the reconnect retry path.
func (rs RedisStorage) storeDirectoryRecord(ctx context.Context, client redis.UniversalClient, key string, score float64, repair, baseIsDir bool) error {

	// Extract parent directory and base (file) names from key
	dir, base := rs.splitDirectoryKey(key, baseIsDir)
	// Reached the top-level directory
	if dir == "." {
		return nil
	}

	// Insert "base" value into Set "dir"
	success, err := client.ZAdd(ctx, dir, redis.Z{Score: score, Member: base}).Result()
	if err != nil {
		return fmt.Errorf("Unable to add %s to Set %s: %v", base, dir, err)
	}

	// Non-zero success means base was added to the set (not already there)
	if success > 0 || repair {
		if success > 0 && repair {
			if rs.logger != nil {
				rs.logger.Infof("Repaired index for record '%s' in directory '%s'", base, dir)
			}
		}
		// recursively create parent directory until already
		// created (success == 0) or top level reached
		if err := rs.storeDirectoryRecord(ctx, client, dir, score, repair, true); err != nil {
			return err
		}
	}

	return nil
}

// Delete record from directory index Redis ZSet structure.
// The client argument is threaded through recursive calls and the
// existence check so a single op stays on one client (cached or one-shot).
func (rs RedisStorage) deleteDirectoryRecord(ctx context.Context, client redis.UniversalClient, key string, baseIsDir bool) error {

	dir, base := rs.splitDirectoryKey(key, baseIsDir)
	// Reached the top-level directory
	if dir == "." {
		return nil
	}

	// Remove "base" value from Set "dir"
	if err := client.ZRem(ctx, dir, base).Err(); err != nil {
		return fmt.Errorf("Unable to remove %s from Set %s: %v", base, dir, err)
	}

	// Check if Set "dir" still exists (removing the last item deletes the set)
	exists, err := rs.existsRawKey(ctx, client, dir)
	if err != nil {
		return fmt.Errorf("Unable to check existence for %s: %v", dir, err)
	}
	if !exists {
		// Recursively delete parent directory until parent
		// is not empty (exists > 0) or top level reached
		if err := rs.deleteDirectoryRecord(ctx, client, dir, true); err != nil {
			return err
		}
	}

	return nil
}

func (rs RedisStorage) splitDirectoryKey(key string, baseIsDir bool) (string, string) {

	dir := path.Dir(key)
	base := path.Base(key)

	// Append slash to indicate directory
	if baseIsDir {
		base = base + keyPathSeparator
	}

	return dir, base
}

// String returns a JSON representation of the configuration with sensitive fields redacted.
// The value receiver is intentional: Password and EncryptionKey are mutated on the copy
// so the original struct is never modified.
func (rs RedisStorage) String() string {
	redacted := `REDACTED`
	if rs.Password != "" {
		rs.Password = redacted
	}
	if rs.EncryptionKey != "" {
		rs.EncryptionKey = redacted
	}
	strVal, _ := json.Marshal(rs)
	return string(strVal)
}

// GetClient returns the Redis client initialized by this storage.
//
// This is useful for other modules that need to interact with the same Redis instance.
// The return type of GetClient is "any" for forward-compatibility new versions of go-redis.
// The returned value must usually be cast to redis.UniversalClient.
func (rs *RedisStorage) GetClient() any {
	return rs.client
}
