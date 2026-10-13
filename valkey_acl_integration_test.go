package storageredis

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Opt-in: needs Docker. `go test ./...` skips it unless the variable is set.
const valkeyACLEnv = "APX_VALKEY_ACL_INTEGRATION"

// APX_VALKEY_IMAGE overrides the server image (default valkey/valkey:9.1).
const defaultValkeyImage = "valkey/valkey:9.1"

// pluginACLCommands is every command the plugin sends on the storage, lock
// and handshake paths, and nothing else. A per-cluster ACL user needs exactly
// these (plus key patterns for its prefix). HELLO is not listed because it is
// flagged no-auth and bypasses command rules. The admin-only `caddy redis
// repair` command also needs SCAN and TYPE, which cluster users must not get.
var pluginACLCommands = []string{
	// handshake (go-redis): SELECT when db > 0, CLIENT SETNAME when
	// client_name is set, CLIENT SETINFO always (a denial is ignored by
	// go-redis but still written to ACL LOG)
	"select", "client|setname", "client|setinfo",
	// Provision
	"ping",
	// Store, Load, Stat, Exists, List, Delete
	"get", "set", "del", "exists", "zadd", "zrem", "zrange",
	// Lock, lock refresh and Unlock run redislock scripts: EVALSHA, then
	// EVAL on NOSCRIPT. Valkey checks every command a script calls against
	// the caller's rules.
	"evalsha", "eval", "getrange", "pexpire",
}

type valkeyServer struct {
	addr  string
	admin *redis.Client
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return fmt.Sprintf("%x", b)
}

func startValkey(t *testing.T) *valkeyServer {
	t.Helper()
	image := os.Getenv("APX_VALKEY_IMAGE")
	if image == "" {
		image = defaultValkeyImage
	}
	name := "apx-valkey-acl-" + randomHex(t, 8)
	adminPassword := randomHex(t, 16)

	// The default user gets a password, as in production, so an
	// unauthenticated connection cannot fall back to it.
	out, err := exec.Command("docker", "run", "--detach", "--rm", "--name", name,
		"--publish", "127.0.0.1::6379", image,
		"valkey-server", "--save", "", "--appendonly", "no",
		"--requirepass", adminPassword, "--acllog-max-len", "1024").CombinedOutput()
	require.NoError(t, err, "starting Valkey: %s", out)
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "rm", "--force", name).CombinedOutput(); err != nil {
			t.Errorf("removing %s: %s: %v", name, out, err)
		}
	})

	out, err = exec.Command("docker", "port", name, "6379/tcp").CombinedOutput()
	require.NoError(t, err, "%s", out)
	addr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)

	admin := redis.NewClient(&redis.Options{Addr: addr, Password: adminPassword, Protocol: 2})
	t.Cleanup(func() { _ = admin.Close() })
	ctx := context.Background()
	require.Eventually(t, func() bool { return admin.Ping(ctx).Err() == nil }, 15*time.Second, 50*time.Millisecond)

	info, err := admin.Info(ctx, "server").Result()
	require.NoError(t, err)
	version := infoField(info, "valkey_version")
	t.Logf("server %s valkey_version=%s", image, version)
	if image == defaultValkeyImage {
		require.True(t, strings.HasPrefix(version, "9.1."), "expected Valkey 9.1.x, got %q", version)
	}

	return &valkeyServer{addr: addr, admin: admin}
}

func infoField(info, field string) string {
	for line := range strings.SplitSeq(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), field+":"); ok {
			return v
		}
	}
	return ""
}

// setUser creates a user limited to one key prefix (the bare root
// directory key and everything below prefix/), one database and cmds.
func (s *valkeyServer) setUser(t *testing.T, user, password, prefix string, db int, cmds []string) {
	t.Helper()
	args := []any{"ACL", "SETUSER", user, "reset", "on", ">" + password, "resetchannels",
		fmt.Sprintf("db=%d", db), "~" + prefix, "~" + prefix + "/*", "-@all"}
	for _, c := range cmds {
		args = append(args, "+"+c)
	}
	require.NoError(t, s.admin.Do(context.Background(), args...).Err())
}

// aclLog returns the ACL LOG entries recorded for user.
func (s *valkeyServer) aclLog(t *testing.T, user string) []map[string]string {
	t.Helper()
	raw, err := s.admin.Do(context.Background(), "ACL", "LOG", "1024").Slice()
	require.NoError(t, err)
	var entries []map[string]string
	for _, r := range raw {
		fields, ok := r.([]any)
		require.True(t, ok, "unexpected ACL LOG entry %T", r)
		entry := map[string]string{}
		for i := 0; i+1 < len(fields); i += 2 {
			entry[fmt.Sprint(fields[i])] = fmt.Sprint(fields[i+1])
		}
		if entry["username"] == user {
			entries = append(entries, entry)
		}
	}
	return entries
}

// commandStats returns the commands the server has executed or rejected
// since the last CONFIG RESETSTAT.
func (s *valkeyServer) commandStats(t *testing.T) []string {
	t.Helper()
	info, err := s.admin.Info(context.Background(), "commandstats").Result()
	require.NoError(t, err)
	var cmds []string
	for line := range strings.SplitSeq(info, "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if cmd, found := strings.CutPrefix(name, "cmdstat_"); ok && found {
			cmds = append(cmds, cmd)
		}
	}
	sort.Strings(cmds)
	return cmds
}

type aclWorkloadConfig struct {
	username, password, prefix, db string
	clientName                     string
	encryptionKey                  string
	decryptionKeys                 []string
	holdLockForRefresh             bool
}

func newACLStorage(cfg aclWorkloadConfig, addr string) *RedisStorage {
	rs := New()
	logger, _ := zap.NewProduction()
	rs.logger = logger.Sugar()
	rs.Address = []string{addr}
	rs.Username = cfg.username
	rs.Password = cfg.password
	rs.DB = DBIndex(cfg.db)
	rs.KeyPrefix = cfg.prefix
	rs.Timeout = "5"
	rs.Compression = CompressionFlate
	rs.EncryptionKey = cfg.encryptionKey
	rs.DecryptionKeys = slices.Clone(cfg.decryptionKeys)
	rs.ClientName = cfg.clientName
	return rs
}

// runACLWorkload drives every storage path certmagic uses: provisioning,
// Store, Exists, Load, Stat, recursive List, a contended Lock (so the obtain
// script reaches GETRANGE), optionally a lock refresh (PEXPIRE), Unlock and
// Delete. It returns the first error. The storage stays connected until the
// test ends, so the caller can inspect CLIENT LIST.
func runACLWorkload(t *testing.T, addr string, cfg aclWorkloadConfig) error {
	t.Helper()
	ctx := context.Background()

	rs := newACLStorage(cfg, addr)
	if err := rs.finalizeConfiguration(ctx); err != nil {
		return fmt.Errorf("provision: %w", err)
	}
	t.Cleanup(func() { _ = rs.Cleanup() })

	contender := newACLStorage(cfg, addr)
	if err := contender.finalizeConfiguration(ctx); err != nil {
		return fmt.Errorf("provision contender: %w", err)
	}
	t.Cleanup(func() { _ = contender.Cleanup() })

	paths := []string{
		"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt",
		"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.key",
		"certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.json",
	}

	if rs.Exists(ctx, paths[0]) {
		return errors.New("exists before store")
	}
	for _, p := range paths {
		if err := rs.Store(ctx, p, []byte("value of "+p)); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	if !rs.Exists(ctx, paths[0]) {
		return errors.New("exists after store returned false")
	}
	for _, p := range paths {
		got, err := rs.Load(ctx, p)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		if string(got) != "value of "+p {
			return fmt.Errorf("load %s returned %q", p, got)
		}
	}
	if _, err := rs.Stat(ctx, paths[0]); err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	listed, err := rs.List(ctx, "certificates", true)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	if len(listed) != len(paths) {
		return fmt.Errorf("list returned %v", listed)
	}

	const lockName = "issue_cert_example.com"
	if err := rs.Lock(ctx, lockName); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	contendCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	err = contender.Lock(contendCtx, lockName)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		_ = rs.Unlock(ctx, lockName)
		return fmt.Errorf("contended lock: expected a wait, got %v", err)
	}
	if cfg.holdLockForRefresh {
		time.Sleep(lockRefreshInterval + time.Second)
	}
	if err := rs.Unlock(ctx, lockName); err != nil {
		return fmt.Errorf("unlock: %w", err)
	}

	for _, p := range paths {
		if err := rs.Delete(ctx, p); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
	}
	if rs.Exists(ctx, paths[0]) {
		return errors.New("exists after delete returned true")
	}
	return nil
}

func TestValkeyACL(t *testing.T) {
	if os.Getenv(valkeyACLEnv) != "1" {
		t.Skipf("set %s=1 to run against a Docker Valkey (%s)", valkeyACLEnv, defaultValkeyImage)
	}
	srv := startValkey(t)
	ctx := context.Background()

	t.Run("plugin works with only its prefix, its database and its commands", func(t *testing.T) {
		user, password, prefix := "fleet_test_ps123_g1", randomHex(t, 21), "caddy_test_ps123"
		srv.setUser(t, user, password, prefix, 1, pluginACLCommands)

		passwordFile := filepath.Join(t.TempDir(), "password")
		require.NoError(t, os.WriteFile(passwordFile, []byte(password+"\n"), 0o600))
		t.Setenv("APX_ACL_TEST_USER", user)
		t.Setenv("APX_ACL_TEST_ENCRYPTION_KEY", clusterTestKey)
		t.Setenv("APX_ACL_TEST_APP", "apx-test-ps-123")
		t.Setenv("APX_ACL_TEST_MACHINE", "m"+randomHex(t, 6))
		wantName := "apx-test-ps-123/" + os.Getenv("APX_ACL_TEST_MACHINE")

		// Seed a record written with the fleet key, as an F1 machine would.
		seed := newACLStorage(aclWorkloadConfig{username: user, password: password, prefix: prefix, db: "1", encryptionKey: fleetTestKey}, srv.addr)
		require.NoError(t, seed.finalizeConfiguration(ctx))
		t.Cleanup(func() { _ = seed.Cleanup() })
		require.NoError(t, seed.Store(ctx, "seed/fleet.crt", []byte("fleet")))

		// Start with an empty script cache so EVAL (the NOSCRIPT fallback)
		// runs, and count only what this workload sends.
		require.NoError(t, srv.admin.ScriptFlush(ctx).Err())
		require.NoError(t, srv.admin.ConfigResetStat(ctx).Err())

		cfg := aclWorkloadConfig{
			username:           "{env.APX_ACL_TEST_USER}",
			password:           "{file." + passwordFile + "}",
			prefix:             prefix,
			db:                 "1",
			clientName:         "{env.APX_ACL_TEST_APP}/{env.APX_ACL_TEST_MACHINE}",
			encryptionKey:      "{env.APX_ACL_TEST_ENCRYPTION_KEY}",
			decryptionKeys:     []string{fleetTestKey},
			holdLockForRefresh: true,
		}
		require.NoError(t, runACLWorkload(t, srv.addr, cfg))

		// F2 reads the F1 record through decryption_keys.
		reader := newACLStorage(cfg, srv.addr)
		require.NoError(t, reader.finalizeConfiguration(ctx))
		t.Cleanup(func() { _ = reader.Cleanup() })
		got, err := reader.Load(ctx, "seed/fleet.crt")
		require.NoError(t, err)
		assert.Equal(t, "fleet", string(got))

		observed := srv.commandStats(t)
		t.Logf("commands sent: %v", observed)
		errorStats, err := srv.admin.Info(ctx, "errorstats").Result()
		require.NoError(t, err)
		t.Logf("errorstats: %q", strings.TrimSpace(errorStats))

		assert.Empty(t, srv.aclLog(t, user), "ACL LOG must stay empty")

		// Exactly the granted commands, plus HELLO (no-auth) and the
		// admin's own CONFIG RESETSTAT.
		want := append(slices.Clone(pluginACLCommands), "hello", "config|resetstat")
		sort.Strings(want)
		assert.Equal(t, want, observed)

		clients, err := srv.admin.ClientList(ctx).Result()
		require.NoError(t, err)
		named := 0
		for line := range strings.SplitSeq(clients, "\n") {
			if strings.Contains(line, " user="+user+" ") && strings.Contains(line, " name="+wantName+" ") {
				named++
			}
		}
		assert.Positive(t, named, "CLIENT LIST shows the configured name:\n%s", clients)
	})

	t.Run("every granted command is needed", func(t *testing.T) {
		for i, missing := range pluginACLCommands {
			t.Run(missing, func(t *testing.T) {
				user := fmt.Sprintf("fleet_test_minus%d_g1", i)
				password := randomHex(t, 21)
				prefix := fmt.Sprintf("caddy_test_minus%d", i)
				srv.setUser(t, user, password, prefix, 1, slices.DeleteFunc(slices.Clone(pluginACLCommands), func(c string) bool { return c == missing }))
				require.NoError(t, srv.admin.ScriptFlush(ctx).Err())

				err := runACLWorkload(t, srv.addr, aclWorkloadConfig{
					username: user, password: password, prefix: prefix, db: "1",
					clientName:         "acl-teeth",
					encryptionKey:      clusterTestKey,
					holdLockForRefresh: missing == "pexpire",
				})
				denied := srv.aclLog(t, user)
				t.Logf("without %s: workload error: %v; ACL LOG: %v", missing, err, denied)
				assert.True(t, err != nil || len(denied) > 0, "removing %s went unnoticed", missing)
			})
		}
	})

	t.Run("prefix rule does not reach a longer cluster id", func(t *testing.T) {
		user, password := "fleet_test_ps77_g1", randomHex(t, 21)
		srv.setUser(t, user, password, "caddy_test_ps77", 1, pluginACLCommands)

		err := runACLWorkload(t, srv.addr, aclWorkloadConfig{
			username: user, password: password, prefix: "caddy_test_ps778", db: "1",
			encryptionKey: clusterTestKey,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NOPERM")
		denied := srv.aclLog(t, user)
		require.NotEmpty(t, denied)
		assert.Equal(t, "key", denied[0]["reason"])
	})

	t.Run("db rule refuses another database", func(t *testing.T) {
		user, password, prefix := "fleet_test_ps78_g1", randomHex(t, 21), "caddy_test_ps78"
		srv.setUser(t, user, password, prefix, 1, pluginACLCommands)

		err := runACLWorkload(t, srv.addr, aclWorkloadConfig{
			username: user, password: password, prefix: prefix, db: "2",
			encryptionKey: clusterTestKey,
		})
		require.Error(t, err)
		t.Logf("db 2: %v", err)
		assert.Contains(t, err.Error(), "NOPERM")
	})

	t.Run("missing or wrong credentials fail closed", func(t *testing.T) {
		user, password, prefix := "fleet_test_ps79_g1", randomHex(t, 21), "caddy_test_ps79"
		srv.setUser(t, user, password, prefix, 1, pluginACLCommands)

		for name, cfg := range map[string]aclWorkloadConfig{
			"unset password": {username: user, password: "{env.APX_ACL_TEST_UNSET_PASSWORD}"},
			"unset username": {username: "{env.APX_ACL_TEST_UNSET_USER}", password: password},
			"wrong password": {username: user, password: password + "x"},
		} {
			t.Run(name, func(t *testing.T) {
				cfg.prefix, cfg.db, cfg.encryptionKey = prefix, "1", clusterTestKey
				rs := newACLStorage(cfg, srv.addr)
				err := rs.finalizeConfiguration(ctx)
				if err == nil {
					_ = rs.Cleanup()
				}
				require.Error(t, err)
				t.Logf("%s: %v", name, err)
			})
		}

		t.Run("unset decryption key", func(t *testing.T) {
			rs := newACLStorage(aclWorkloadConfig{
				username: user, password: password, prefix: prefix, db: "1",
				encryptionKey:  clusterTestKey,
				decryptionKeys: []string{"{env.APX_ACL_TEST_UNSET_KEY}"},
			}, srv.addr)
			err := rs.finalizeConfiguration(ctx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "decryption_keys")
		})
	})
}
