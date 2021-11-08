package main

import (
	"database/sql"
	"errors"
	"net"
	"time"

	"github.com/rs/zerolog/log"
)

//shortban and longban upsert SQL commands because you can't parameterize table names in Go
var shortBanUpsert string = "INSERT INTO  short_ban(ip, ts_added) VALUES ($1, $2) ON CONFLICT(ip) DO UPDATE SET ts_added = $2;"
var longBanUpsert string = "INSERT INTO  long_ban(ip, ts_added) VALUES ($1, $2) ON CONFLICT(ip) DO UPDATE SET ts_added = $2;"

// shortban and longban cleanup statements
var shortBanCleanup string = "DELETE FROM short_ban where ts_added < now() - ($1 || ' HOURS')::INTERVAL;"
var longBanCleanup string = "DELETE FROM long_ban where ts_added < now() - ($1 || ' HOURS')::INTERVAL;"
var logonAuditCleanup string = "DELETE FROM logon_audit where ts < now() - ($1 || ' HOURS')::INTERVAL;"

// get ips commands
var shortBanIPs string = "SELECT ip from short_ban"
var longBanIPs string = "SELECT ip from long_ban"

// CreateTablesIfNotExist creates the sql tables in the DB if they don't exist
func CreateTablesIfNotExist(db *sql.DB) {
	// note that the longest length IP address is an IPv6 mapped to IPv4 address
	// https://stackoverflow.com/questions/1076714/max-length-for-client-ip-address/7477384#7477384
	// ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190

	// at time of writing, max username length is 120:
	tables := [3]string{
		`CREATE TABLE IF NOT EXISTS logon_audit (
			id SERIAL PRIMARY KEY,
			ts TIMESTAMP,
			ip VARCHAR(45),
			username VARCHAR(120),
			pwhash VARCHAR(100),
			reason VARCHAR(100),
			ignore boolean DEFAULT FALSE
		);`,
		`CREATE TABLE IF NOT EXISTS short_ban(
			id SERIAL PRIMARY KEY,
			ip varchar(45) UNIQUE,
			ts_added TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS long_ban(
			id SERIAL PRIMARY KEY,
			ip varchar(45) UNIQUE,
			ts_added TIMESTAMP);`,
	}
	for _, sqlstring := range tables {
		stmt, err := db.Prepare(sqlstring)
		if err != nil {
			log.Fatal().Str("Error", err.Error()).Msg("cannot prepare SQL statement")
		}
		_, err = stmt.Exec()
		if err != nil {
			log.Fatal().Str("Error", err.Error()).Msg("Could not create SQL table")
		}
	}
}

// InsertEvent puts a new event into the database
func InsertEvent(db *sql.DB, record *NewFailure) error {
	if record.IP == "" {
		return errors.New("IP cannot be blank")
	}
	parsedIP := net.ParseIP(record.IP)
	if parsedIP == nil {
		return errors.New("Failed to parse IP")
	}
	insertSQL := `INSERT INTO logon_audit
	(ts,ip,username,pwhash,reason) VALUES ($1, $2, $3, $4, $5);`
	_, err := db.Exec(insertSQL, record.Ts.Format(time.RFC3339), record.IP, record.Username, record.Pwhash, record.Reason)
	if err != nil {
		log.Error().Str("Error", err.Error()).Msg("Error inserting record into DB")
		return err
	}
	return nil
}

// CheckAndInsert checks to see if an IP should be added to `tablename`
func CheckAndInsert(db *sql.DB, record *NewFailure, table string, period, limit int) {
	// get the count from the DB
	log.Debug().Msg("Running CheckAndInsert")
	checksql := `SELECT count(*)
		FROM logon_audit
		WHERE ip = $1
		AND ignore = FALSE
		AND ts > now() - ($2 || ' HOURS')::INTERVAL;
		`

	var ipcount int
	row := db.QueryRow(checksql, record.IP, period)
	err := row.Scan(&ipcount)
	if err != nil {
		log.Error().Str("Error", err.Error()).Msg("Error getting count from logon audit")
		return
	}
	if ipcount >= limit {
		log.Debug().
			Str("Table", table).
			Str("IP", record.IP).
			Str("Time", time.Now().Format(time.RFC3339)).
			Msg("IP over limit - banning")
		var insertStmt string
		if table == "short_ban" {
			insertStmt = shortBanUpsert
		} else if table == "long_ban" {
			insertStmt = longBanUpsert
		} else {
			log.Error().
				Str("Table", table).
				Str("IP", record.IP).
				Msg("Check/insert: Invalid table name")
			return
		}
		// "INSERT INTO  short_ban(ip, ts_added) VALUES ($1, $2) ON CONFLICT(ip) DO UPDATE SET ts_added = $2;"
		_, err := db.Exec(insertStmt, record.IP, time.Now().Format(time.RFC3339))
		if err != nil {
			log.Error().Str("Error", err.Error()).Msg("Error inserting record into ban table")
		} else {
			log.Info().Str("IP", record.IP).Str("Added Time", time.Now().Format(time.RFC3339)).Msg("Inserting into ban table")
		}
	}
}

// CleanOldSQL removes old records from the table
func CleanOldSQL(db *sql.DB, table string, intervalHours int) {
	var cleanSQL string
	if table == "short_ban" {
		cleanSQL = shortBanCleanup
	} else if table == "long_ban" {
		cleanSQL = longBanCleanup
	} else if table == "logon_audit" {
		cleanSQL = logonAuditCleanup
	} else {
		log.Error().
			Str("Table", table).
			Msg("Cleanup: Invalid table name")
		return
	}
	_, err := db.Exec(cleanSQL, intervalHours)
	if err != nil {
		log.Error().Str("Table", table).Str("Error", err.Error()).Msg("Error deleting old records from the DB")
	} else {
		log.Debug().Str("Table", table).Msg("Cleaned up old/expired bans")
	}
}

// GetRecords gets IP addresses from the table name provided.
// This function also appends the "/32" to the IP address which is
// required by AWS WAF to add to the blocklist
func GetRecords(db *sql.DB, table string, iplist map[string]*string) {
	var query string
	if table == "short_ban" {
		query = shortBanIPs
	} else if table == "long_ban" {
		query = longBanIPs
	} else {
		log.Error().
			Str("Table", table).
			Msg("GetRecords: Invalid table name")
		return
	}
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Error getting IP from row on table %s: %s", table, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		err = rows.Scan(&ip)
		if err != nil {
			log.Printf("Error getting IP from row in table %s: %s", table, err)
			continue
		}
		// modify the IP to have a CIDR value
		// TODO: handle this more gracefully in the future
		ip = ip + "/32"
		iplist[ip] = &ip
		//*iplist = append(*iplist, &ip)
	}
}

// IgnoreIPRecords will ignore the history of an IP address in the database
func IgnoreIPRecords(db *sql.DB, ip string, c chan error) {
	updateSQL := `UPDATE logon_audit SET ignore = TRUE where ip = $1;`
	_, err := db.Exec(updateSQL, ip)
	if err != nil {
		log.Error().Str("Error", err.Error()).Str("IP", ip).Msg("Error ignoring IP in DB")
		c <- err
	}
	removeShort := `DELETE FROM short_ban WHERE ip = $1;`
	removeLong := `DELETE FROM long_ban WHERE ip = $1;`
	_, err = db.Exec(removeShort, ip)
	if err != nil {
		log.Error().Str("Error", err.Error()).Str("IP", ip).Msg("Error deleting IP in short ban list")
		c <- err
	}
	_, err = db.Exec(removeLong, ip)
	if err != nil {
		log.Error().Str("Error", err.Error()).Str("IP", ip).Msg("Error deleting IP in long ban list")
		c <- err
	}
	c <- nil
}
