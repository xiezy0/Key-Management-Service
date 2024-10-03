package routers

import (
	"BFT/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Init(router *gin.Engine) {
	handler := handlers.NewBFTHandler()

	// 接口地址
	router.GET("/recover_pri_poly", handler.RecoverPriPoly)
	// 运行命令
	router.GET("/cmds", handler.RunCmds)
	router.GET("/ws", handler.Ws)
	// 前端web静态处理
	router.StaticFS("/index", http.Dir("./static/web"))
}
