package database

import (
	"database/sql"
	"domain-security-checker/internal/types"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	conn *sql.DB
}

func New(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	db := &DB{conn: conn}
	if err := db.createTables(); err != nil {
		return nil, err
	}
    fmt.Println("Database connected successfully")
	return db, nil
	
}

func (db *DB) createTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS domain_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		has_mx BOOLEAN,
		has_spf BOOLEAN,
		spf_record TEXT,
		has_dmarc BOOLEAN,
		dmarc_record TEXT,
		checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_domain ON domain_results(domain);
	`
	_, err := db.conn.Exec(query)
	return err
}

func (db *DB) SaveResult(result *types.DomainResult) error {
	query := `
	INSERT INTO domain_results (domain, has_mx, has_spf, spf_record, has_dmarc, dmarc_record, checked_at)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.conn.Exec(query, result.Domain, result.HasMX, result.HasSPF,
		result.SPFRecord, result.HasDMARC, result.DMARCRecord, result.CheckedAt)
	return err
}

func (db *DB) GetHistory(domain string, limit int) ([]*types.DomainResult, error) {
	query := `
	SELECT id, domain, has_mx, has_spf, spf_record, has_dmarc, dmarc_record, checked_at
	FROM domain_results 
	WHERE domain = ? 
	ORDER BY checked_at DESC 
	LIMIT ?
	`

	rows, err := db.conn.Query(query, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.DomainResult
	for rows.Next() {
		result := &types.DomainResult{}
		err := rows.Scan(&result.ID, &result.Domain, &result.HasMX, &result.HasSPF,
			&result.SPFRecord, &result.HasDMARC, &result.DMARCRecord, &result.CheckedAt)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}



