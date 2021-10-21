# goburplikerepeater
```
cat ./example.http | go run main.go -x localhost:8080 -t https://csp.yandex.net
go run main.go -x localhost:8080 -t https://csp.yandex.net --json example.http example.http example.http example.http example.http
```

# DEV
```
go run main.go -x localhost:8080 -t https://oauthaccountmanager.googleapis.com  --json ~/hack/myrequests/testluaplugin.http | python  -c "import json; from rich import print; i = json.loads(input()); print(i['request']); print(i['response'])"
```
