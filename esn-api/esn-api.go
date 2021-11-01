package esnapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-basic/uuid"
)

func MakeESNSession(address string, user string, pass string, timeout int) (*ESNSession, error) {
	var session ESNSession
	if len(strings.Split(address, ":")) < 2 {
		address = address + ":3003"
	}
	c, err := net.Dial("tcp", address)
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
	go session.AliveLoop()
	return &session, nil
}

type ISessionListener interface {
	NotificationReceived(ntf PackRespNotification)
	SessionLogout(err PackResult)
}

func (session *ESNSession) SetListener(sessionListener ISessionListener) {
	session.SessionListener = sessionListener
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
			if session.SessionListener != nil {
				respNoti := &PackRespNotification{}
				err = json.Unmarshal([]byte(p.Json), respNoti)
				if err != nil {
					continue
				}
				session.SessionListener.NotificationReceived(*respNoti)
			}
		} else if tokenPack.Token == "LogoutPackage" { //logout
			if session.SessionListener != nil {
				logout := &PackResult{}
				err = json.Unmarshal([]byte(p.Json), logout)
				if err != nil {
					continue
				}
				session.SessionListener.SessionLogout(*logout)
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

func RSA_encrypter(key string, msg []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(key))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
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
	return rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipherText)

}

func randToken() string {
	uuid := uuid.New()
	return uuid
}
