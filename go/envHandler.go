package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// EnvConfig is the configuration from the environmental vars
type EnvConfig struct {
	Regions         []string
	BlockListName   string
	DBHostname      string
	DBPort          int
	DBpw            string
	SecretName      string
	DBUserName      string
	DBName          string
	ShortTermPeriod int
	LongTermPeriod  int
	ShortTermLimit  int
	LongTermLimit   int
	RetentionPeriod int
	UpdateRate      int
}

// GetEnvVars returns a configuration object from the environmental vars
func GetEnvVars() EnvConfig {
	regions := strings.Split(getVar("AWS_REGION", "us-east-1"), ",")
	blocklistName := getVar("BLOCKLIST_NAME", "autoblocklist-DEV")
	dbhost := getVar("DB_HOSTNAME", "localhost")
	dbport := getVarInt("DB_PORT", 5432)
	secretName := getVar("SECRET_NAME", "dev/autowaf/db")
	// database configs
	// TODO: update for CF
	dbUsername := getVar("DB_USER", "postgres")
	dbName := getVar("DB_NAME", "postgres")
	dbPw := getVar("DB_PASSWORD", "mysecretpassword")
	// 10 failed attempts in 6 hours ban
	// https://github.banksimple.com/backend/everything/pull/10927/files
	shortPeriod := getVarInt("SHORT_PERIOD", 6)
	shortLimit := getVarInt("SHORT_LIMIT", 10)
	// 15 failed attempts in 30 days
	longPeriod := getVarInt("LONG_PERIOD", 720)
	longLimit := getVarInt("LONG_LIMIT", 15)
	// retention period
	retPeriod := getVarInt("RETENTION_PERIOD", 90)
	//
	updateRate := getVarInt("UPDATE_RATE", 5)

	return EnvConfig{
		Regions:         regions,
		BlockListName:   blocklistName,
		DBHostname:      dbhost,
		DBPort:          dbport,
		SecretName:      secretName,
		DBUserName:      dbUsername,
		DBName:          dbName,
		DBpw:            dbPw,
		ShortTermLimit:  shortLimit,
		ShortTermPeriod: shortPeriod,
		LongTermLimit:   longLimit,
		LongTermPeriod:  longPeriod,
		RetentionPeriod: retPeriod,
		UpdateRate:      updateRate,
	}
}

func getVar(varname, defaultVal string) string {
	envvar := os.Getenv(varname)
	if envvar == "" {
		envvar = defaultVal
	}
	return envvar
}

func getVarInt(varname string, defaultVal int) int {
	envvar := getVar(varname, strconv.Itoa(defaultVal))
	n, err := strconv.Atoi(envvar)
	if err == nil {
		return n
	}
	log.Fatalf("Error in converting environmental variable to an integer: %s", err)
	return -1
}
