# autowaf

A service which updates the WAF IP blocklist

# Development

Project is currently in development phase.

## Build
### Build and run locally

```shell
go build -o autowaf && ./autowaf -ldb
```
The `-ldb` argument will change the database port to `54300` and change the `update-rate` to 1 minute. It will also prevent the app from trying to get database credentials from cloudfoundry environmental variables.


### Environmental vars
#### BLOCKLIST_NAME
`BLOCKLIST_NAME` is the name of the blocklist to update on the WAF. Defaults to: `autoblocklist-DEV`

#### AWS_REGION
`AWS_REGION` is a comma separated list with the AWS region(s) of the blocklist(s). It defaults to `us-east-1`. Currently 1+ regions are supported.

#### SHORT_PERIOD
`SHORT_PERIOD` is the duration used for a short term ban query. It defaults to `6` (*hours*) and must be an integer.

#### LONG_PERIOD
`LONG_PERIOD` is the duration used for a long term ban query. It defaults to `720` (*hours*) and must be an integer.

#### SHORT_LIMIT
`SHORT_LIMIT` is the limiting number of requests over `SHORT_PERIOD` that results in a short term ban. It defaults to `10` and must be an integer.

#### LONG_LIMIT
`LONG_LIMIT` is the limiting number of requests over `LONG_PERIOD` that results in a long term ban. It defaults to `15` and must be an integer.

#### UPDATE_RATE
`UPDATE_RATE` is the number of *minutes* before the background thread updates the WAF. It defaults to `5`.

#### RETENTION_PERIOD
`RETENTION_PERIOD` is the number of *days* to keep records in the logon_audit table. It defaults to `90` and must be an integer.

#### DB_USER
`DB_USER` is the username used for connecting to a postgres database. It is ignored unless `-ldb` is passed. It defaults to `postgres`.

#### DB_NAME
`DB_NAME` is the database named used for connecting to a postgres database. It is ignored unless `-ldb` is passed. It defaults to `postgres`.

#### DB_PASSWORD
`DB_PASSWORD` is the database password used when connecting to a postgres database. It is ignored unless `-ldb` is passed. It defaults to `mysecretpassword`.

#### DB_HOSTNAME
`DB_HOSTNAME` is the database hostname used when connecting to a postgres database. It is ignored unless `-ldb` is passed. It defaults to `localhost`.

## API

#### /loginfailure
This API takes in a JSON object with the following fields:

* ts: a timestamp in RFC3339 format

* ip: the IP address that’s the source of the failed login attempt. Can be IPv4, IPv6 or IPv4 vis IPv6

* username: the username of the failed login attempt

* pwhash: [optional] the password hash

* reason: the reason for the failure (e.g. PASSWORD_FAILURE)

The service will return the following status code:

* 200: Success

* 422: Unprocessable Entity - there was a problem with the JSON object passed to the API

* 500: Other internal error occurred in the service

#### /unblockIP
This API takes in a JSON object with the following fields:

* ip: the IP address to be unbanned

The service will return the following status code:

* 200: Success - Whether or not IP was found in database or blocklist

* 422: Unprocessable Entity - there was a problem with the JSON object passed to the API

* 500: Other internal error occurred in the service

#### /healthcheck

The healthcheck API takes in no values and returns a 200 if the service is healthy.

