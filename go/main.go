package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/cloudfoundry-community/go-cfenv"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var db *sql.DB
var awsSessions []*session.Session
var envConfig EnvConfig

// NewFailure is the event coming in for logon failures
type NewFailure struct {
	Ts       time.Time `json:"ts"`
	IP       string    `json:"ip"`
	Username string    `json:"username"`
	Pwhash   string    `json:"pwhash"`
	Reason   string    `json:"reason"`
}

// HealthCheck is the oject returned to a health check
type HealthCheck struct {
	Status string
}

// UnbanRequest is the request object to unban an IP
type UnbanRequest struct {
	IP string `json:"ip"`
}

// updateBlockLists is the background task that runs on a timer
func updateBlockLists(ticker *time.Ticker, quit *chan string) {
	for {
		select {
		case <-ticker.C:
			log.Debug().Msg("Starting WAF update task")
			// clean
			CleanOldSQL(db, "short_ban", envConfig.ShortTermPeriod)
			CleanOldSQL(db, "long_ban", envConfig.LongTermPeriod)
			CleanOldSQL(db, "logon_audit", envConfig.RetentionPeriod*60)
			// get new+current
			iplist := make(map[string]*string)
			GetRecords(db, "short_ban", iplist)
			GetRecords(db, "long_ban", iplist)

			log.Debug().Msg("Outputting IPs to ban")
			//make a list of pointers to the ips
			//needed for UpdateIPSet() UpdateIPSetInput
			ipStrPnts := make([]*string, len(iplist))
			cntr := 0
			for ipaddr := range iplist {
				log.Debug().Str("IP", ipaddr).Msg("Banning IP")
				ipStrPnts[cntr] = iplist[ipaddr]
				cntr = cntr + 1
			}
			//update AWS regions
			for _, session := range awsSessions {
				wafclient := wafv2.New(session)
				ipset, err := GetIPSet(wafclient.ListIPSets, &envConfig)
				if err != nil {
					log.Error().
						Str("Error", err.Error()).
						Str("IPset Name", envConfig.BlockListName).
						Msg("Couldn't find an ipset")
					continue
				}
				// error is handled/logged in this function
				_ = UpdateIPSet(ipStrPnts, wafclient.UpdateIPSet, ipset)
			}
		case <-*quit:
			ticker.Stop()
			log.Debug().Msg("Exiting background timer")
			return
		}
	}
}

// APIs
func logonFailureWriter(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("Logon Failure Writer Starting")
	// get the new record from the request
	var newRecord NewFailure
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		log.Warn().Str("Error", err.Error()).Msg("Error reading http request body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Warn().Str("Error", err.Error()).Msg("Error closing request body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(body, &newRecord); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			panic(err)
		}
		return
	}
	// write the new record to the database
	err = InsertEvent(db, &newRecord)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Debug().Msg("Inserted event into logon_audit")
	//async call check and inserts
	go CheckAndInsert(db, &newRecord, "short_ban", envConfig.ShortTermPeriod, envConfig.ShortTermLimit)
	go CheckAndInsert(db, &newRecord, "long_ban", envConfig.LongTermPeriod, envConfig.LongTermLimit)
	//return to user
	w.WriteHeader(http.StatusOK)
}

func healthCheckWriter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthCheck{Status: "OK"})
}

func unblockIP(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("New unblock IP request")
	var unbanObj UnbanRequest
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	//read input
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		log.Warn().Str("Error", err.Error()).Msg("Error reading http request body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Warn().Str("Error", err.Error()).Msg("Error closing request body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(body, &unbanObj); err != nil {
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			panic(err)
		}
		return
	}

	trueErr := 0
	// update the DB
	c := make(chan error)
	go IgnoreIPRecords(db, unbanObj.IP, c)

	//update AWS
	for _, session := range awsSessions {
		wafclient := wafv2.New(session)
		err := RemoveIPfromIPSet(wafclient.ListIPSets, wafclient.GetIPSet,
			wafclient.UpdateIPSet, &envConfig, &unbanObj.IP)
		if (err != nil) && (err != ErrIPNotFound) {
			trueErr += 1
		}
	}

	//get result from db update
	dberr := <-c
	if dberr != nil {
		trueErr += 1
	}

	if trueErr != 0 {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func main() {
	// command line args
	noBgTaskFlag := flag.Bool("nobgtask", false, "turn off the background task that updates the WAF")
	localDbgFlag := flag.Bool("ldb", false, "")
	flag.Parse()
	// parse environmental variables
	envConfig = GetEnvVars()
	if *localDbgFlag {
		envConfig.DBPort = 54320
		envConfig.UpdateRate = 1
	}
	var pgURI string
	if !*localDbgFlag {
		appEnv, _ := cfenv.Current()
		rdsService, err := appEnv.Services.WithNameUsingPattern(".{1,}-autowaf")
		if err != nil {
			log.Fatal().Str("Error", err.Error()).Msg("Failed to find autowaf service in env")
		}

		var ok bool
		pgURI, ok = rdsService[0].CredentialString("uri")
		if !ok {
			log.Fatal().Msg("Couldn't load pg URI from cfenv")
		}
	}
	// configure logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Debug().Msg("Logging has been set up")

	// setup aws session with each region
	for _, region := range envConfig.Regions {
		log.Debug().Msg("Setting up AWS Session with region: " + region)
		// The reason we need to set sessionRegion to region is a weird quirk in golang
		// that makes &region point to only the first item in the list.
		sessionRegion := region
		awsSessions = append(awsSessions, session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Config: aws.Config{
				Region: &sessionRegion,
			},
		})))
	}
	// for _, session := range awsSessions {
	// 	log.Info().Str("region", *session.Config.Region).Msg("Debug region")
	// }

	// setup DB
	var err error
	var psqlInfo string
	if !*localDbgFlag {
		psqlInfo = pgURI
	} else {
		psqlInfo = fmt.Sprintf("host=%s port=%d user=%s "+
			"password=%s dbname=%s sslmode=disable",
			envConfig.DBHostname, envConfig.DBPort, envConfig.DBUserName, envConfig.DBpw, envConfig.DBName)
	}

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal().Str("Error", err.Error()).Msg("Couldn't open database")
	}

	log.Debug().Msg("Creating database tables (if not exists)")
	CreateTablesIfNotExist(db)

	// create background task that updates the WAF
	ticker := time.NewTicker(time.Duration(envConfig.UpdateRate) * time.Minute)
	quit := make(chan string)
	if !*noBgTaskFlag {
		go updateBlockLists(ticker, &quit)
	}

	// setup URL handlers/routes
	r := mux.NewRouter()
	r.HandleFunc("/logonfailure", logonFailureWriter).Methods("POST")
	r.HandleFunc("/healthcheck", healthCheckWriter).Methods("GET")
	r.HandleFunc("/unblockIP", unblockIP).Methods("POST")

	log.Debug().Msg("Starting http handler")
	http.ListenAndServe(":8080", r)
	quit <- "quit"
}
