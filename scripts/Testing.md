# Testing

### Manual Testing Procedure

#### Preparation
0. Make sure you are on the VPN.
1. In environment, set SHORT_PERIOD=1 (1 hour), LONG_PERIOD=2 (2 hours), SHORT_LIMIT=5, LONG_LIMIT=10. UPDATE_RATE can also be shortened from the default of 5 minutes.
2. Restart the application so it can get the new variable settings.
3. Use the post_logonfailure.sh and post_unblockIP.sh scripts to send the api calls. For steps where JSON is provided, replace that line in the script before execution.
4. Use `cf logs autowaf` in another terminal tab to view the output.
5. Some steps refer to "each region" or "all regions". Currently this means us-west-1 and us-west-2.
6. You can do other tests while waiting for the ban limits to expire as long as you use different IPs.


#### /loginfailure
1. Send /loginfailure with incorrect fields or with missing fields.

   Expected: Script will show HTTP 422 was received. Logs will show request received and "Logon Failure Writer Starting".

   a. Missing json key:
      JSON=\`printf '{"ts": "%s", "ip": "%s", "username": "bob", "pwhash": "abc123", PASSWORD_FAILURE"}' $TIME $1\`

   b. Bad IP:
      JSON=\`printf '{"ts": "%s", "ip": "%s", "username": "bob", "pwhash": "abc123", "reason": PASSWORD_FAILURE"}' $TIME '8.8.8'\`

   c. Bad time:
      JSON=\`printf '{"ts": "%s", "ip": "%s", "username": "bob", "pwhash": "abc123", "reason": PASSWORD_FAILURE"}' 'blah' $1\`

2. Send /loginfailure with correct fields.

   Expected: Script will show HTTP 200 was received. Logs will show request received, "Logon Failure Writer Starting", "Inserted event into logon_audit", and "Running CheckAndInsert" twice.

3. Send /loginfailure three more times (so now one under SHORT_LIMIT).

   Expected: Each request completed successfully, no log entries indicate that IP was added to ban list.

4. Send /loginfailure 1 more time (so now equal to SHORT_LIMIT).

   Expected: Logs will show "short_ban", "IP over limit - banning", and "Inserting into ban table". Within 5 minutes you will see the logs indicate that it is "Starting WAF update task". Ensure that the log says "Outputting IPs to ban" followed by the IP you used with the script. Ensure that further down it says "Found blocklist with name..." once for each region. This indicates that it was able to update the blocklist in all regions. Go to AWS Firewall Manager and check that the IP is in the blocklist in all regions.

5. Send /loginfailure 5 times for another IP address.

   Expected: Logs will show "short_ban", "IP over limit - banning", and "Inserting into ban table". Within 5 minutes you will see the logs indicate that it is "Starting WAF update task". Ensure that the log says "Outputting IPs to ban" followed by both IPs. Ensure that further down it says "Found blocklist with name..." once for each region. This indicates that it was able to update the blocklist in all regions. Go to AWS Firewall Manager and check that both IPs are in the blocklist in all regions.

6. Wait for 1 hour (SHORT_PERIOD).

   Expected: While you wait notice that every 5 minutes it continues to check if the WAF needs updating. The IPs will continue to be shown in the "Outputting IPs to ban" list. When it is about five minutes before the hour go back into AWS and ensure the IPs haven't been removed early. When it reaches an hour since the first IP was added to the list, the logs will show the WAF updating task but will not include the first IP in the "Outputting IPs to ban" list. Ensure the first IP has been removed from all regions in AWS. When it reaches an hour since the second IP was added to the list, the logs will show the WAF updating task but will not include the second IP in the "Outputting IPs to ban" list. Ensure the second IP has been removed from all regions in AWS. Now neither IP should be banned.

7. Send /loginfailure 10 times (LONG_LIMIT) for two different IPs. Try to do this within the five minute update window so they both get added to the list at the same time.

   Expected: Logs will show the IPs in both the "short_ban" and "long_ban" lists with the text "IP over limit - banning", and "Inserting into ban table". Within 5 minutes you will see the logs indicate that it is "Starting WAF update task". Ensure that the log says "Outputting IPs to ban" followed by the IPs you used with the script. Ensure that further down it says "Found blocklist with name..." once for each region. This indicates that it was able to update the blocklist in all regions. Go to AWS Firewall Manager and check that both IPs are in the blocklist in all regions.

8. Wait for 2 hours (LONG_PERIOD).

   Expected: While you wait notice that every 5 minutes it continues to check if the WAF needs updating. The IPs will continue to be shown in the "Outputting IPs to ban" list. When it is about five minutes before the 2 hour mark go back into AWS and ensure the IPs haven't been removed early. When it reaches two hours since the IPs were added to the list, the logs will show the WAF updating task but will not include the IPs in the "Outputting IPs to ban" list. Ensure the IPs have been removed from all regions in AWS.


#### /unblockIP
1. Send /unblockIP with incorrect fields or with missing fields.

   a. Bad IP:
      JSON=\`printf '{"ip": "%s"}' '8.8.8'\`

      Expected: Script will show HTTP 500 was received. Logs will show request received and "New unblock IP request".

   b. No IP:
      JSON=\`\`

      Expected: Script will show HTTP 422 was received. Logs will show request received and "New unblock IP request".


2. Send /unblockIP for IP that isn't blocked.

   Expected: Script will show HTTP 200 was received. Logs will show request received and "Tried to remove IP that wasn't in blocklist" twice.

3. Send /loginfailure 10 times (LONG_LIMIT) for two different IPs. Wait for them to be added to the blocklist in AWS. Send /unblockIP with correct fields for the first IP. Send /unblockIP with correct fields for the second IP.

   Expected: Script will show HTTP 200 was received for each of the /logonfailure and /unblockIP requests. The IPs will be successfully added to the blocklist in all AWS regions. Ensure that each time /unblockIP is sent, the log shows "New unblock IP request" followed by two instances of "Removed IP from blocklist". Ensure only the specified IP is removed from the blocklist (in all AWS regions) each time the request is sent.

4. Send /loginfailure 10 times (LONG_LIMIT) for one IP. Before the WAF update task runs, send /unblockIP.

    Expect: Script will show HTTP 200 was received. Logs will show request received and "Tried to remove IP that wasn't in blocklist" twice. IP is not added to blocklist next time the Update WAF task runs.

#### /healthcheck
1. With app running send /healthcheck.

   Expected: Script will show HTTP 200 was received. Logs will show the request being received.

   curl -i http://localhost:8080/healthcheck


#### Rebooting
1. With IPs already in blocklist for SHORT_PERIOD, restart application in CF.

   Expected: After restart, can see the IPs as still banned in the WAF update task logs and in AWS. After SHORT_PERIOD the IPs should be removed. Note that because the Updating WAF task occurs every five minutes from when autowaf is started, it is possible for the IP to be removed a few minutes early/late because the cadence of the update has changed.

2. What if database somehow loses all of its information (e.g. container is rebuilt), but there are still IPs in the blocklist?

   Expected: No need to test. Likely autowaf would erase all of the IPs in the blocklist and start from scratch, but it doesn't really matter. If an attack is ongoing, it will just block the IP again. If an attack is over, then it doesn't matter that the IP was unblocked early.

#### Corner Cases / FAQ
1. What if IP exists in blocklist but not database?

   Expected: No need to test. Next time autowaf does WAF update task, it removes the extra IP.

2. What if blocklist in each region is different?

   Expected: No need to test. This can only happen if I manually add or remove an IP to/from the blocklist in AWS. Autowaf will make the blocklist conform with the database. Extra IPs will be removed, removed IPs will be added again.

3. What if ipset has duplicates?

   Expected: No need to test. Invalid because AWS doesn't seem to allow duplicates to exist.

4. What if I manually add IP with non /32 suffix?

   Expected: No need to test. Invalid because AWS seems to only accept /32 as a suffix. AWS does not allow an IP without a suffix.

5. Load test.

   Expected: We are not testing this specifically. During dev, this will be done through use. We will not being taking the logic to handle this out of Carmel, so if autowaf does crash for whatever reason, there will be a backup.

7. Does daylight savings time affect the ban length?

   Expected: No need to test. autowaf uses UTC so it is unlikely that DST will affect anything. However, even if it does, that will only cause a ban to be off by an hour twice a year which is an acceptable amount of error.
