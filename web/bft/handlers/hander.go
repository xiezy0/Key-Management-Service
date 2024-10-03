package handlers

import (
	"BFT/response"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"sync"

	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
var ws *websocket.Conn
var mu sync.Mutex

type bftHandler struct{}

func NewBFTHandler() *bftHandler {
	return &bftHandler{}
}

type Client struct {
	// 启动的顺序
	ID         int
	TypeClient int
	ParaClient int
}

type Server struct {
	ServerNum int
}

// 接口处理handler
func (*bftHandler) RecoverPriPoly(c *gin.Context) {
	n, err := strconv.Atoi(c.Query("n"))
	if err != nil {
		c.JSON(http.StatusOK, response.Response{
			Code: -1,
			Data: "类型错误",
		})
		return
	}

	// 这是调用库里的代码
	suite := edwards25519.NewBlakeSHA256Ed25519()
	t := n/2 + 1
	a := share.NewPriPoly(suite, t, nil, suite.RandomStream())

	shares := a.Shares(n)
	reverses := make([]*share.PriShare, len(shares))
	l := len(shares) - 1
	for i := range shares {
		reverses[l-i] = shares[i]
	}
	recovered, err := share.RecoverPriPoly(suite, shares, t, n)
	if err != nil {
		c.JSON(http.StatusOK, response.Response{
			Code: -1,
			Data: err.Error(),
		})
		return
	}

	reverseRecovered, err := share.RecoverPriPoly(suite, reverses, t, n)
	if err != nil {
		c.JSON(http.StatusOK, response.Response{
			Code: -1,
			Data: err.Error(),
		})
		return
	}

	data := make(map[string]interface{}, 3)
	aSlice := make([]string, 0)
	recoveredSlice := make([]string, 0)
	reverseRecoveredSlice := make([]string, 0)

	for i := 0; i < t; i++ {
		aSlice = append(aSlice, a.Eval(i).V.String())
		recoveredSlice = append(recoveredSlice, recovered.Eval(i).V.String())
		reverseRecoveredSlice = append(reverseRecoveredSlice, reverseRecovered.Eval(i).V.String())
	}
	data["t"] = t
	data["a"] = aSlice
	data["recovered"] = recoveredSlice
	data["reverseRecovered"] = reverseRecoveredSlice

	c.JSON(http.StatusOK, response.Response{
		Code: 0,
		Data: data,
	})
}

func (*bftHandler) RunCmds(c *gin.Context) {
	cmds := `
		go run main.go
	`
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmds)
	} else {
		cmd = exec.Command("bash", "-c", cmds)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusOK, response.Response{
			Code: -1,
			Data: err.Error(),
		})
	}
	c.JSON(http.StatusOK, response.Response{
		Code: 0,
		Data: string(output),
	})
}

func (*bftHandler) Ws(c *gin.Context) {
	var err error
	ws, err = upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	for {
		mt, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}

		v := make(map[string]interface{})
		_ = json.Unmarshal(msg, &v)
		num, _ := strconv.Atoi(v["num"].(string))
		type_server_client := v["type"].(string)
		if type_server_client == "0" {
			startClients(num, mt)
		} else {
			startServers(num, mt)
		}
	}
}

func startServers(n, mt int) {
	for i := 0; i < n; i++ {
		var c *exec.Cmd
		server := &Server{ServerNum: i}
		cmd := fmt.Sprintf(`cd .. && cd hacss && server.exe %d`, server.ServerNum)

		if runtime.GOOS == "windows" {
			c = exec.Command("cmd", "/C", cmd)
		} else {
			c = exec.Command("bash", "-c", cmd)
		}
		fmt.Println("执行命令为：" + cmd)

		std, err := c.StdoutPipe()
		if err != nil {
			fmt.Printf("%d 报错了：%s\n", server.ServerNum, err)
		}
		// 标准输出
		go readServer(server, std, false)

		stderr, err := c.StderrPipe()
		if err != nil {
			fmt.Printf("%d 报错了：%s\n", server.ServerNum, err)
		}
		// 标准错误
		go readServer(server, stderr, true)

		_ = c.Start()
	}
}

func startClients(n, mt int) {
	var c *exec.Cmd
	client := &Client{ID: n,
		TypeClient: 0,
		ParaClient: 1}
	cmd := fmt.Sprintf(`cd .. && cd hacss && client.exe %d %d %d`, client.ID, client.TypeClient, client.ParaClient)

	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", cmd)
	} else {
		c = exec.Command("bash", "-c", cmd)
	}
	fmt.Println("执行命令为：" + cmd)

	std, err := c.StdoutPipe()
	if err != nil {
		fmt.Printf("%d 报错了：%s\n", client.ID, err)
	}
	// 标准输出
	go read(client, std, false)

	stderr, err := c.StderrPipe()
	if err != nil {
		fmt.Printf("%d 报错了：%s\n", client.ID, err)
	}
	// 标准错误
	go read(client, stderr, true)

	_ = c.Start()

}

func read(client *Client, reader io.Reader, isErr bool) {
	readout := bufio.NewReader(reader)
	for {
		readString, err := readout.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Printf("%d：结束了\n", client.ID)
			} else {
				fmt.Printf("%d：报错了：%s\n", client.ID, err.Error())
			}
			return
		}

		code := 0
		if isErr {
			code = -1
		}
		res, err := json.Marshal(map[string]interface{}{
			"code":               code,
			"data":               fmt.Sprintf("%d：", client.ID) + readString,
			"type_client_server": "0",
		})
		if err != nil {
			fmt.Printf("%d 报错了：%s\n", client.ID, err.Error())
			return
		}

		mu.Lock()
		ws.WriteMessage(websocket.TextMessage, res)
		mu.Unlock()
	}
}

func readServer(server *Server, reader io.Reader, isErr bool) {
	readout := bufio.NewReader(reader)
	for {
		readString, err := readout.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Printf("%d：结束了\n", server.ServerNum)
			} else {
				fmt.Printf("%d：报错了：%s\n", server.ServerNum, err.Error())
			}
			return
		}

		code := 0
		if isErr {
			code = -1
		}
		res, err := json.Marshal(map[string]interface{}{
			"code":               code,
			"data":               fmt.Sprintf("%d：", server.ServerNum) + readString,
			"type_client_server": "1",
		})
		if err != nil {
			fmt.Printf("%d 报错了：%s\n", server.ServerNum, err.Error())
			return
		}

		mu.Lock()
		ws.WriteMessage(websocket.TextMessage, res)
		mu.Unlock()
	}
}
