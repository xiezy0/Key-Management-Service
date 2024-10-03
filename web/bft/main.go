package main

import (
	"BFT/middle"
	"BFT/routers"

	"github.com/gin-gonic/gin"
)

// CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build main.go
func main() {
	router := gin.Default()
	router.Use(middle.Cors())
	routers.Init(router)
	_ = router.Run(":8888")
}
