package storageredis

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	fleetTestKey   = "fleet-key-0123456789abcdefghijkl" // 32 bytes
	clusterTestKey = "cluster-key-0123456789abcdefghij" // 32 bytes
	otherTestKey   = "other-key-0123456789abcdefghijkl" // 32 bytes
)

// sealWithKey builds a value in the plugin's documented wire layout
// (12-byte nonce prefix, AES-256-GCM ciphertext, 16-byte tag suffix)
// without going through the plugin, so the layout itself is pinned.
func sealWithKey(t *testing.T, key string, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher([]byte(key))
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func openWithKey(key string, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}

func TestDecrypt_WireLayoutUnchanged(t *testing.T) {
	plaintext := []byte("certificate bytes")

	rs := New()
	rs.EncryptionKey = fleetTestKey

	got, err := rs.decrypt(sealWithKey(t, fleetTestKey, plaintext))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	sealed, err := rs.encrypt(plaintext)
	require.NoError(t, err)
	got, err = openWithKey(fleetTestKey, sealed)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestDecrypt_FallsBackToDecryptionKeysInOrder(t *testing.T) {
	plaintext := []byte("certificate bytes")

	rs := New()
	rs.EncryptionKey = clusterTestKey
	rs.DecryptionKeys = []string{otherTestKey, fleetTestKey}

	for _, key := range []string{clusterTestKey, otherTestKey, fleetTestKey} {
		got, err := rs.decrypt(sealWithKey(t, key, plaintext))
		require.NoError(t, err, "sealed with %q", key[:5])
		assert.Equal(t, plaintext, got)
	}
}

func TestDecrypt_NoKeyMatchesKeepsDecryptionFailure(t *testing.T) {
	rs := New()
	rs.EncryptionKey = clusterTestKey
	rs.DecryptionKeys = []string{fleetTestKey}

	got, err := rs.decrypt(sealWithKey(t, otherTestKey, []byte("x")))
	assert.Nil(t, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Decryption failure")
	assert.Contains(t, err.Error(), "message authentication failed")
}

func TestDecrypt_ShortCiphertextNotRetriedWithOtherKeys(t *testing.T) {
	rs := New()
	rs.EncryptionKey = clusterTestKey
	rs.DecryptionKeys = []string{fleetTestKey}

	got, err := rs.decrypt(make([]byte, 27))
	assert.Nil(t, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid encrypted data")
}

func TestEncrypt_AlwaysUsesEncryptionKey(t *testing.T) {
	rs := New()
	rs.EncryptionKey = clusterTestKey
	rs.DecryptionKeys = []string{fleetTestKey}

	sealed, err := rs.encrypt([]byte("x"))
	require.NoError(t, err)

	_, err = openWithKey(clusterTestKey, sealed)
	require.NoError(t, err)
	_, err = openWithKey(fleetTestKey, sealed)
	require.Error(t, err)
}

// newPhaseStorage provisions one storage instance against a shared
// miniredis, as one machine of a cluster would be in a given phase.
func newPhaseStorage(t *testing.T, mr *miniredis.Miniredis, encryptionKey string, decryptionKeys ...string) *RedisStorage {
	t.Helper()
	rs := New()
	logger, _ := zap.NewProduction()
	rs.logger = logger.Sugar()
	rs.Address = []string{mr.Addr()}
	rs.KeyPrefix = "caddy_test_ps123"
	rs.Compression = CompressionFlate
	rs.EncryptionKey = encryptionKey
	rs.DecryptionKeys = decryptionKeys
	require.NoError(t, rs.finalizeConfiguration(context.Background()))
	t.Cleanup(func() { _ = rs.Cleanup() })
	return rs
}

// TestKeyRotationPhases walks the F1 to F4 phases of the per-cluster
// encryption key change. Machines of one cluster pick up a new config at
// different times, so each phase must read what its neighbours write.
func TestKeyRotationPhases(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	ctx := context.Background()

	legacy := newPhaseStorage(t, mr, fleetTestKey)
	f1 := newPhaseStorage(t, mr, fleetTestKey, clusterTestKey)
	f2 := newPhaseStorage(t, mr, clusterTestKey, fleetTestKey)
	f4 := newPhaseStorage(t, mr, clusterTestKey)

	phases := map[string]*RedisStorage{"legacy": legacy, "f1": f1, "f2": f2, "f4": f4}
	// readable[writer] lists the phases that must read what writer stores.
	readable := map[string][]string{
		"legacy": {"legacy", "f1", "f2"},
		"f1":     {"legacy", "f1", "f2"},
		"f2":     {"f1", "f2", "f4"},
		"f4":     {"f1", "f2", "f4"},
	}
	// unreadable[writer] lists the phases that must fail closed.
	unreadable := map[string][]string{
		"legacy": {"f4"},
		"f1":     {"f4"},
		"f2":     {"legacy"},
		"f4":     {"legacy"},
	}

	for writer, ws := range phases {
		key := "certificates/acme/example.com/" + writer + ".crt"
		value := []byte("value written by " + writer)
		require.NoError(t, ws.Store(ctx, key, value))

		for _, reader := range readable[writer] {
			got, err := phases[reader].Load(ctx, key)
			require.NoError(t, err, "%s must read what %s writes", reader, writer)
			assert.Equal(t, value, got)
		}
		for _, reader := range unreadable[writer] {
			got, err := phases[reader].Load(ctx, key)
			assert.Nil(t, got)
			require.Error(t, err, "%s must not read what %s writes", reader, writer)
			assert.Contains(t, err.Error(), "Decryption failure")
		}
	}
}

func TestFinalizeConfiguration_DecryptionKeys(t *testing.T) {
	t.Run("env placeholder expanded and truncated to 32 bytes", func(t *testing.T) {
		t.Setenv("APX_TEST_DECRYPTION_KEY", clusterTestKey+"extra")
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}
		rs.EncryptionKey = fleetTestKey
		rs.DecryptionKeys = []string{"{env.APX_TEST_DECRYPTION_KEY}"}

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		assert.Equal(t, []string{clusterTestKey}, rs.DecryptionKeys)
	})

	t.Run("file placeholder expanded", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key")
		require.NoError(t, os.WriteFile(path, []byte(clusterTestKey+"\n"), 0o600))
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}
		rs.EncryptionKey = fleetTestKey
		rs.DecryptionKeys = []string{"{file." + path + "}"}

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		assert.Equal(t, []string{clusterTestKey}, rs.DecryptionKeys)
	})

	t.Run("encryption_key placeholder still expanded alongside", func(t *testing.T) {
		t.Setenv("APX_TEST_ENCRYPTION_KEY", clusterTestKey)
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}
		rs.EncryptionKey = "{env.APX_TEST_ENCRYPTION_KEY}"
		rs.DecryptionKeys = []string{fleetTestKey}

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		assert.Equal(t, clusterTestKey, rs.EncryptionKey)
		assert.Equal(t, []string{fleetTestKey}, rs.DecryptionKeys)
	})

	t.Run("missing env secret fails closed", func(t *testing.T) {
		rs := New()
		rs.EncryptionKey = fleetTestKey
		rs.DecryptionKeys = []string{"{env.APX_TEST_DECRYPTION_KEY_UNSET}"}

		err := rs.finalizeConfiguration(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid length for 'decryption_keys' entry 0")
	})

	t.Run("short key rejected without echoing it", func(t *testing.T) {
		rs := New()
		rs.EncryptionKey = fleetTestKey
		rs.DecryptionKeys = []string{clusterTestKey, "short-secret-value"}

		err := rs.finalizeConfiguration(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid length for 'decryption_keys' entry 1")
		assert.NotContains(t, err.Error(), "short-secret-value")
	})

	t.Run("requires encryption_key", func(t *testing.T) {
		rs := New()
		rs.DecryptionKeys = []string{fleetTestKey}

		err := rs.finalizeConfiguration(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'decryption_keys' requires 'encryption_key'")
	})

	t.Run("duplicates of encryption_key and repeats are dropped", func(t *testing.T) {
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}
		rs.EncryptionKey = fleetTestKey
		rs.DecryptionKeys = []string{fleetTestKey, clusterTestKey, clusterTestKey + "x", otherTestKey}

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		assert.Equal(t, []string{clusterTestKey, otherTestKey}, rs.DecryptionKeys)
	})

	t.Run("empty list is a no-op", func(t *testing.T) {
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}
		rs.DecryptionKeys = []string{}

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		assert.Empty(t, rs.DecryptionKeys)
	})
}

func TestFinalizeConfiguration_ClientName(t *testing.T) {
	t.Run("placeholders expanded and sent to the server", func(t *testing.T) {
		t.Setenv("APX_TEST_APP", "apx-dev-ps-89")
		t.Setenv("APX_TEST_MACHINE", "d8d9e1")
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}
		rs.ClientName = "{env.APX_TEST_APP}/{env.APX_TEST_MACHINE}"

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		t.Cleanup(func() { _ = rs.Cleanup() })
		assert.Equal(t, "apx-dev-ps-89/d8d9e1", rs.ClientName)

		name, err := rs.client.ClientGetName(context.Background()).Result()
		require.NoError(t, err)
		assert.Equal(t, "apx-dev-ps-89/d8d9e1", name)
	})

	t.Run("unset by default", func(t *testing.T) {
		rs, mr := newFinalizeTestStorage(t)
		rs.Address = []string{mr.Addr()}

		require.NoError(t, rs.finalizeConfiguration(context.Background()))
		t.Cleanup(func() { _ = rs.Cleanup() })

		name, err := rs.client.ClientGetName(context.Background()).Result()
		require.Error(t, err) // redis.Nil: no name was set
		assert.Empty(t, name)
	})

	t.Run("characters Redis refuses are rejected at provision", func(t *testing.T) {
		for _, bad := range []string{"has space", "new\nline", "tab\t", "café"} {
			rs := New()
			rs.ClientName = bad

			err := rs.finalizeConfiguration(context.Background())
			require.Error(t, err, "%q", bad)
			assert.Contains(t, err.Error(), "invalid 'client_name'")
		}
	})
}

func TestUnmarshalCaddyfile_DecryptionKeysAndClientName(t *testing.T) {
	t.Run("single value", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`redis {
			encryption_key "{env.NEW_KEY}"
			decryption_keys "{env.OLD_KEY}"
			client_name "{env.FLY_APP_NAME}/{env.FLY_MACHINE_ID}"
		}`)
		rs := New()
		require.NoError(t, rs.UnmarshalCaddyfile(d))
		assert.Equal(t, "{env.NEW_KEY}", rs.EncryptionKey)
		assert.Equal(t, []string{"{env.OLD_KEY}"}, rs.DecryptionKeys)
		assert.Equal(t, "{env.FLY_APP_NAME}/{env.FLY_MACHINE_ID}", rs.ClientName)
	})

	t.Run("block of values keeps order", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`redis {
			encryption_key "{env.NEW_KEY}"
			decryption_keys {
				"{env.OLD_KEY}"
				"{file./run/secrets/older_key}"
			}
		}`)
		rs := New()
		require.NoError(t, rs.UnmarshalCaddyfile(d))
		assert.Equal(t, []string{"{env.OLD_KEY}", "{file./run/secrets/older_key}"}, rs.DecryptionKeys)
	})
}

func TestJSON_DecryptionKeysAndClientName(t *testing.T) {
	var rs RedisStorage
	require.NoError(t, json.Unmarshal([]byte(`{
		"encryption_key": "{env.APX_STORAGE_ENCRYPTION_KEY}",
		"decryption_keys": ["fleet-literal", "{env.OLDER}"],
		"client_name": "{env.FLY_APP_NAME}/{env.FLY_MACHINE_ID}"
	}`), &rs))
	assert.Equal(t, []string{"fleet-literal", "{env.OLDER}"}, rs.DecryptionKeys)
	assert.Equal(t, "{env.FLY_APP_NAME}/{env.FLY_MACHINE_ID}", rs.ClientName)
}

// The pre-change field set, as RedisStorage.String() rendered it at
// 1c804cd. Configs without the new fields must render byte-identically.
const legacyStringGolden = `{"client_type":"simple","address":null,"host":["127.0.0.1"],"port":["6379"],"db":"0","timeout":"","username":"u","password":"REDACTED","sentinel_password":"","master_name":"","key_prefix":"caddy","encryption_key":"REDACTED","compression":"","tls_enabled":false,"tls_insecure":false,"tls_server_certs_pem":"","tls_server_certs_path":"","route_by_latency":false,"route_randomly":false}`

func TestString_UnchangedWithoutNewFields(t *testing.T) {
	rs := New()
	rs.Username = "u"
	rs.Password = "x"
	rs.EncryptionKey = "y"
	assert.Equal(t, legacyStringGolden, rs.String())
}

func TestString_RedactsDecryptionKeysWithoutMutatingThem(t *testing.T) {
	rs := New()
	rs.EncryptionKey = fleetTestKey
	rs.DecryptionKeys = []string{clusterTestKey, otherTestKey}
	rs.ClientName = "apx-dev-ps-89/d8d9e1"

	out := rs.String()
	assert.NotContains(t, out, clusterTestKey)
	assert.NotContains(t, out, otherTestKey)

	var decoded RedisStorage
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, []string{"REDACTED", "REDACTED"}, decoded.DecryptionKeys)
	assert.Equal(t, "apx-dev-ps-89/d8d9e1", decoded.ClientName)
	assert.Equal(t, []string{clusterTestKey, otherTestKey}, rs.DecryptionKeys)
}

func TestUnmarshalCaddyfile_ExtraArgsNeverEchoSecrets(t *testing.T) {
	t.Run("decryption_keys accepts several keys on one line", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`redis {
			decryption_keys "first-secret-key-value" "second-secret-key-value"
		}`)
		rs := New()
		require.NoError(t, rs.UnmarshalCaddyfile(d))
		assert.Equal(t, []string{"first-secret-key-value", "second-secret-key-value"}, rs.DecryptionKeys)
	})

	for _, key := range []string{"encryption_key", "aes_key", "password", "sentinel_password", "username", "client_name"} {
		t.Run(key+" rejects extra values without echoing them", func(t *testing.T) {
			d := caddyfile.NewTestDispenser(`redis {
				` + key + ` "first-secret-value" "second-secret-value"
			}`)
			rs := New()
			err := rs.UnmarshalCaddyfile(d)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "too many values on one line for configuration key '"+key+"'")
			assert.NotContains(t, err.Error(), "first-secret-value")
			assert.NotContains(t, err.Error(), "second-secret-value")
		})
	}

	t.Run("block form of a single-value key is unchanged", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(`redis {
			password {
				"block-secret"
			}
		}`)
		rs := New()
		require.NoError(t, rs.UnmarshalCaddyfile(d))
		assert.Equal(t, "block-secret", rs.Password)
	})
}

func TestString_RedactsSentinelPassword(t *testing.T) {
	rs := New()
	rs.SentinelPassword = "sentinel-secret"

	out := rs.String()
	assert.NotContains(t, out, "sentinel-secret")

	var decoded RedisStorage
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, "REDACTED", decoded.SentinelPassword)
	assert.Equal(t, "sentinel-secret", rs.SentinelPassword)
}
