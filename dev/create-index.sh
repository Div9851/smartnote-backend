source env.sh
curl -X PUT -H "Content-Type: application/json" -d @create-index.json $BONSAI_URL/$INDEX_NAME