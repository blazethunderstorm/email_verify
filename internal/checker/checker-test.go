package checker

import (
    "domain-security-checker/internal/database"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

func TestChecker_CheckDomain(t *testing.T) {
    db, err := database.New(":memory:")
    assert.NoError(t, err)
    defer db.Close()

    checker := New(5*time.Second, false, db)

    t.Run("Check valid domain with MX records", func(t *testing.T) {
        result, err := checker.CheckDomain("google.com")
        assert.NoError(t, err)
        assert.NotNil(t, result)
        assert.Equal(t, "google.com", result.Domain)
        assert.True(t, result.HasMX)
    })

    t.Run("Check domain with SPF record", func(t *testing.T) {
        result, err := checker.CheckDomain("github.com")
        assert.NoError(t, err)
        assert.NotNil(t, result)
        assert.Equal(t, "github.com", result.Domain)
        assert.True(t, result.HasMX)
        assert.True(t, result.HasSPF)
        assert.Contains(t, result.SPFRecord, "v=spf1")
    })

    t.Run("Check invalid domain", func(t *testing.T) {
        result, err := checker.CheckDomain("invalid-domain-12345.xyz")
        assert.NoError(t, err)
        assert.NotNil(t, result)
        assert.Equal(t, "invalid-domain-12345.xyz", result.Domain)
        assert.False(t, result.HasMX)
        assert.False(t, result.HasSPF)
        assert.False(t, result.HasDMARC)
    })
}