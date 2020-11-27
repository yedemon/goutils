package rtctoken

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"time"
)

const Version = "0.0.1"

// Role Type
type Role uint16

// Role consts
const (
	Publisher = 1
	Watcher   = 2
	Live      = 3
	RoleLast  = 4
)

func random(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

type rtcToken struct {
	AppId         string
	AppToken      string
	RoomName      string //nullable
	Uid           string //nullable
	Role          Role
	Timestamp     uint32
	Salt          string
	Message       map[string]string
	Signature     string
	MsgRawContent string
}

func initToken(appId string, appToken string, roomName string, uid string) rtcToken {
	timestamp := uint32(time.Now().Unix()) + 24*3600
	salt := fmt.Sprint(random(100000, 999999))
	message := make(map[string]string)
	return rtcToken{appId, appToken, roomName, uid, Watcher, timestamp, salt, message, "", ""}
}

func (token *rtcToken) Build() (string, error) {
	queries := url.Values{
		"appId":    {token.AppId},
		"roomName": {token.RoomName},
		"uid":      {token.Uid},
		"role":     {fmt.Sprint(token.Role)},
		"ts":       {fmt.Sprint(token.Timestamp)},
		"salt":     {token.Salt},
		// "version":  {Version},
	}
	query := queries.Encode()

	buf_sig := hmac.New(sha256.New, []byte(token.AppToken))
	buf_sig.Write([]byte(query))
	bytes_sig := buf_sig.Sum(nil)
	sign := fmt.Sprintf("%x", bytes_sig[:])

	data := make(map[string]interface{})
	data["query"] = query
	data["sign"] = sign
	data["ver"] = Version

	bf := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(bf)
	jsonEncoder.SetEscapeHTML(false)
	jsonEncoder.Encode(data)

	ret_token := base64.StdEncoding.EncodeToString(bf.Bytes())

	return ret_token, nil
}

//创建Token方法
// appId: 从CCLive管理后台获取到的 appId
// appToken: 从CCLive管理后台获取到的加密用token
// roomName: 房间名，唯一，可为空字符串"" 暂不支持
// uid: 登录的用户，可为空字符串"" 暂不支持
// role: Publisher = 1: 主播身份 暂未支持
//       Watcher = 2: (默认) 观众身份
//       Live = 3: 互动直播
// expTs: token有效时间, 单位秒 暂未支持
func CreateToken(appId string, appToken string /*roomName string, uid string, role Role, expireSeconds uint32*/) (string, error) {
	// log.Printf("request: %s, %s, %d, %d\n", channelName, uid, role, privilegeExpiredTs)

	roomName := ""
	uid := ""

	token := initToken(appId, appToken, roomName, uid)
	token.Role = Watcher
	return token.Build()
}
