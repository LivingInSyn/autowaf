TIME=`date -u +"%Y-%m-%dT%H:%M:%SZ"`
echo $TIME
JSON=`printf '{"ip": "%s"}' $1`
echo $JSON

curl -XPOST -H "Content-Type: application/json" --data "$JSON" http://localhost:8080/unblockIP
