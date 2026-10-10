module github.com/example/go-app

go 1.21

require (
	github.com/gin-gonic/gin v1.10.0
	github.com/golang-jwt/jwt/v5 v5.2.1 // the comment on a direct require is not "indirect"
	golang.org/x/crypto v0.32.0
)

require (
	github.com/gin-contrib/sse v0.1.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
)

require github.com/example/local v0.0.0

replace golang.org/x/net => golang.org/x/net v0.35.0

replace (
	github.com/example/local => ../local
)

exclude github.com/golang-jwt/jwt/v5 v5.2.0
