package esnapi

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

type ESNSession struct {
	Conn           *net.Conn
	NtfListener    func(ntf PackRespNotification)
	LogoutListener func(err PackResult)
	Protocol       int
	Privilege      string

	wgMap        map[string]*sync.WaitGroup
	receivedPack map[string]*Package
}

func MakeESNSession(addr string, user string, pass string, timeout int) (*ESNSession, error) {
	var session ESNSession
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	session.Conn = &c

	err = WriteInt(119812525, *session.Conn)
	if err != nil {
		return nil, err
	}
	session.Protocol = ReadInt(*session.Conn)

	//login
	var loginPack PackLogin
	loginPack.User = user
	loginPack.Pass = pass
	loginPack.Token = randToken()
	_, err = WritePackage(*session.Conn, loginPack, 1, "")
	if err != nil {
		return nil, err
	}
	//login result
	result := &PackResult{}
	p0, err := ReadPackage(*session.Conn, "")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(p0.Json), &result)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, errors.New(result.Error)
	}

	//request priv
	var pack PackReqPrivList
	pack.Token = randToken()
	_, err = WritePackage(*session.Conn, pack, 6, "")
	if err != nil {
		return nil, err
	}
	result = &PackResult{}
	p0, err = ReadPackage(*session.Conn, "")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(p0.Json), &result)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, errors.New(result.Error)
	}

	//read priv list
	privlist := &PackReqPrivList{}
	privnp, err := ReadPackage(*session.Conn, "")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(privnp.Json), privlist)
	if err != nil {
		return nil, err
	}
	session.Privilege = privlist.Priv

	session.wgMap = make(map[string]*sync.WaitGroup)
	session.receivedPack = make(map[string]*Package)

	go session.readLoop()
	return &session, nil
}
func (session *ESNSession) SetListener(ntfListener func(ntf PackRespNotification), logoutListener func(err PackResult)) {
	session.NtfListener = ntfListener
	session.LogoutListener = logoutListener
}

func (session *ESNSession) readLoop() {
	for {
		p, err := ReadPackage(*session.Conn, "")
		if err != nil {
			fmt.Println(err.Error())
			break
		}

		tokenPack := &PackToken{}
		err = json.Unmarshal([]byte(p.Json), &tokenPack)
		if err != nil {
			fmt.Println(err.Error())
			break
		}

		//check notification
		if p.Code == 5 { //notification received
			if session.NtfListener != nil {
				respNoti := &PackRespNotification{}
				err = json.Unmarshal([]byte(p.Json), respNoti)
				if err != nil {
					continue
				}
				session.NtfListener(*respNoti)
			}
		} else if tokenPack.Token == "LogoutPackage" { //logout
			if session.LogoutListener != nil {
				logout := &PackResult{}
				err = json.Unmarshal([]byte(p.Json), logout)
				if err != nil {
					continue
				}
				session.LogoutListener(*logout)
			}
		} else {
			session.receivedPack[tokenPack.Token] = p
			wg, exist := session.wgMap[tokenPack.Token]
			if exist {
				wg.Done()
			}
		}
	}
}
func (session *ESNSession) selectPack(token string, in interface{}) error {
	//receive 是否存在
	_, exist := session.receivedPack[token]
	if !exist {
		var wg sync.WaitGroup
		session.wgMap[token] = &wg
		wg.Add(1)
		wg.Wait()
		delete(session.wgMap, token)
	}
	err := json.Unmarshal([]byte(session.receivedPack[token].Json), in)
	return err
}

func (session *ESNSession) RequestNotification(from int, limit int) error {
	token := randToken()
	var pack PackRequest
	pack.From = from
	pack.Limit = limit
	pack.Token = token
	_, err := WritePackage(*session.Conn, pack, 4, "")
	if err != nil {
		return err
	}
	result := &PackResult{}
	session.selectPack(token, result)

	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}
func (session *ESNSession) PushNotification(target string, title string, content string) error {
	token := randToken()
	var pack PackPush
	pack.Target = target
	pack.Content = content
	pack.Title = title
	pack.Time = time.Now().Format("2006-01-02,15:04:05")
	pack.Token = token
	_, err := WritePackage(*session.Conn, pack, 3, "")
	if err != nil {
		return err
	}

	result := &PackResult{}
	session.selectPack(token, result)
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

func (session *ESNSession) AddAccount(user string, pass string, privilege string) error {
	token := randToken()
	var pack PackAccountOperation
	pack.Oper = "add"
	pack.Name = user
	pack.Pass = pass
	pack.Token = token
	pack.Kick = false
	pack.Priv = privilege
	_, err := WritePackage(*session.Conn, pack, 7, "")
	if err != nil {
		return err
	}

	result := &PackResult{}
	session.selectPack(token, result)
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

func (session *ESNSession) RemoveAccount(user string, kick bool) error {
	token := randToken()
	var pack PackAccountOperation
	pack.Oper = "remove"
	pack.Kick = kick
	pack.Name = user
	pack.Pass = ""
	pack.Priv = ""
	pack.Token = token
	_, err := WritePackage(*session.Conn, pack, 7, "")
	if err != nil {
		return err
	}

	result := &PackResult{}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

type PackToken struct {
	Token string
}

type PackTest struct { //0 both
	Integer int
	Msg     string
	Token   string
}

type PackLogin struct { //1 client
	User  string
	Pass  string
	Token string
}

type PackResult struct { //2 both
	Result string
	Error  string
	Token  string
}

type PackPush struct { //3 client
	Target  string
	Time    string
	Title   string
	Content string
	Token   string
}

type PackRequest struct { //4 client
	From  int
	Limit int
	Token string
}

type PackRespNotification struct { //5 server
	Id      int
	Target  string
	Time    string
	Title   string
	Content string
	Source  string
	Token   string
}

type PackReqPrivList struct { //6 both
	Priv  string //not nil when server response
	Token string
}

type PackAccountOperation struct { //7 client
	Oper  string //add/remove
	Name  string
	Pass  string
	Priv  string
	Kick  bool
	Token string
}

type PackReqRSAKey struct { //8 client
	Token string
}

type PackRSAPublicKey struct { //9 server
	PublicKey string
	Token     string
}

func WriteInt(n int, conn net.Conn) error {
	x := int32(n)
	err := binary.Write(conn, binary.BigEndian, x)
	return err
}

func ReadInt(conn net.Conn) int {
	// bytesBuffer := bytes.NewBuffer()

	var x int32
	binary.Read(conn, binary.BigEndian, &x)

	return int(x)
}

type Package struct {
	Json   string
	Size   int
	Code   int
	Crypto bool
}

func ReadPackage(conn net.Conn, privateKey string) (*Package, error) {
	var p Package
	p.Code = ReadInt(conn)
	p.Size = ReadInt(conn)
	p.Crypto = ReadInt(conn) == 1
	jsonBytes := make([]byte, p.Size)
	_, err := conn.Read(jsonBytes)
	if err != nil {
		return nil, err
	}
	//加密了
	if p.Crypto {
		DebugMsg("ReadPack", "decrypting:\n"+string(jsonBytes))
		if privateKey == "" {
			return nil, errors.New("no private key to decrypt json")
		}
		de, err := RSA_decrypter(privateKey, jsonBytes)
		if err != nil {
			return nil, err
		}
		jsonBytes = de
	}

	p.Json = string(jsonBytes)
	return &p, nil
}

func WritePackage(conn net.Conn, obj interface{}, code int, rsakey string) (*Package, error) {
	jsonb, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	json := string(jsonb)
	var p Package
	p.Json = json
	p.Code = code
	p.Crypto = rsakey != ""
	dataByte := []byte(json)
	//加密
	if p.Crypto {
		en, err := RSA_encrypter(rsakey, dataByte)
		if err != nil {
			return nil, err
		}
		dataByte = en
	}

	p.Size = len(dataByte)
	err = WriteInt(p.Code, conn)
	if err != nil {
		return nil, err
	}
	err = WriteInt(p.Size, conn)
	if err != nil {
		return nil, err
	}
	cryptoLabel := 0
	if p.Crypto {
		cryptoLabel = 1
	}
	err = WriteInt(cryptoLabel, conn)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(dataByte)
	if err != nil {
		return nil, err
	}
	return &p, err
}

var DebugMode = false

func DebugMsg(sub string, msg string) {
	if DebugMode {
		fmt.Println("Debug-"+sub, msg)
	}
}

func RSA_encrypter(key string, msg []byte) ([]byte, error) {
	//下面的操作是与创建秘钥保存时相反的
	//pem解码
	block, _ := pem.Decode([]byte(key))
	//x509解码,得到一个interface类型的pub
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	//加密操作,需要将接口类型的pub进行类型断言得到公钥类型
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), msg)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}
func RSA_decrypter(key string, cipherText []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(key))
	PrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	//二次解码完毕，调用解密函数
	return rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipherText)

}

func randToken() string {
	mrand.Seed(time.Now().Unix())
	s := time.Now().String() + ":golang:" + strconv.Itoa(mrand.Intn(10000))
	return MD5(s)
}

func MD5Bytes(s []byte) string {
	ret := md5.Sum(s)
	return hex.EncodeToString(ret[:])
}

//计算字符串MD5值
func MD5(s string) string {
	return MD5Bytes([]byte(s))
}
