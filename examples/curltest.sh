curl -X POST https://netbird.ccdev.drpp-onprem.global:443/api/groups \
-H 'Accept: application/json' \
-H 'Content-Type: application/json' \
-H 'Authorization: Token nbp_ZRGn9vZRcL84iB5A0Re7nKpZcKVtgd3yX7kl' \
--data-raw '{
  "name": "curl-test"
}'

curl -X DELETE https://netbird.ccdev.drpp-onprem.global:443/api/groups/cva2g2ck5pjc73dmft00 \
-H 'Authorization: Token nbp_ZRGn9vZRcL84iB5A0Re7nKpZcKVtgd3yX7kl'

curl -X GET https://netbird.scaws04.scaws04ccv2.drpp.global:443/api/groups \
-H 'Authorization: Token nbp_ZRGn9vZRcL84iB5A0Re7nKpZcKVtgd3yX7kl'