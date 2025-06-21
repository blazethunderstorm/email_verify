package types

import "time"

type DomainResult struct {
    ID          int       `json:"id" db:"id"`
    Domain      string    `json:"domain" db:"domain"`
    HasMX       bool      `json:"hasMX" db:"has_mx"`
    HasSPF      bool      `json:"hasSPF" db:"has_spf"`
    SPFRecord   string    `json:"spfRecord" db:"spf_record"`
    HasDMARC    bool      `json:"hasDMARC" db:"has_dmarc"`
    DMARCRecord string    `json:"dmarcRecord" db:"dmarc_record"`
    CheckedAt   time.Time `json:"checkedAt" db:"checked_at"`
}