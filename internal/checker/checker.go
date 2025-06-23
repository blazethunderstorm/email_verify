package checker

import (
	"fmt"
	"domain-security-checker/internal/types"
	"log"
	"net"
	"strings"
	"time"

	"domain-security-checker/internal/database"
)

type Checker struct {
    timeout time.Duration
    verbose bool
    db      *database.DB
}

func New(timeout time.Duration, verbose bool, db *database.DB) *Checker {
    return &Checker{
        timeout: timeout,
        verbose: verbose,
        db:      db,
    }
}

func (c *Checker) CheckDomain(domain string) (*types.DomainResult, error) {
    if c.verbose {
        log.Printf("Checking domain: %s", domain)
    }

    result := &types.DomainResult{
        Domain:    domain,
        CheckedAt: time.Now(),
    }

    if err := c.checkMX(result); err != nil {
        return nil, fmt.Errorf("MX check failed: %w", err)
    }

    if err := c.checkSPF(result); err != nil {
        return nil, fmt.Errorf("SPF check failed: %w", err)
    }

    if err := c.checkDMARC(result); err != nil {
        return nil, fmt.Errorf("DMARC check failed: %w", err)
    }

    if err := c.db.SaveResult(result); err != nil {
        log.Printf("Failed to save result: %v", err)
    }

    return result, nil
}

func (c *Checker) checkMX(result *types.DomainResult) error {
    mxRecords, err := net.LookupMX(result.Domain)
    if err != nil {
        if c.verbose {
            log.Printf("MX lookup failed for %s: %v", result.Domain, err)
        }
        return nil
    }
    result.HasMX = len(mxRecords) > 0
    return nil
}

func (c *Checker) checkSPF(result *types.DomainResult) error {
    txtRecords, err := net.LookupTXT(result.Domain)
    if err != nil {
        if c.verbose {
            log.Printf("TXT lookup failed for %s: %v", result.Domain, err)
        }
        return nil
    }

    for _, record := range txtRecords {
        if strings.HasPrefix(record, "v=spf1") {
            result.HasSPF = true
            result.SPFRecord = record
            break
        }
    }
    return nil
}

func (c *Checker) checkDMARC(result *types.DomainResult) error {
    dmarcDomain := "_dmarc." + result.Domain
    txtRecords, err := net.LookupTXT(dmarcDomain)
    if err != nil {
        if c.verbose {
            log.Printf("DMARC lookup failed for %s: %v", dmarcDomain, err)
        }
        return nil
    }

    for _, record := range txtRecords {
        if strings.HasPrefix(record, "v=DMARC1") {
            result.HasDMARC = true
            result.DMARCRecord = record
            break
        }
    }
    return nil
}

func (c *Checker) GetHistory(domain string, limit int) ([]*types.DomainResult, error) {
    return c.db.GetHistory(domain, limit)
}


