TIME=`date -u +"%Y-%m-%dT%H:%M:%SZ"`
echo $TIME
JSON=`printf '{"ts": "%s", "ip": "%s", "username": "bob", "pwhash": "abc123", "reason": "PASSWORD_FAILURE"}' $TIME $1`
echo $JSON

curl -XPOST -H "Content-Type: application/json" --data "$JSON" http://localhost:8080/logonfailure
