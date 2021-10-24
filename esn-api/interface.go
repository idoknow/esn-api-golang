package esnapi

import (
	"errors"
	"time"
)

/*Count notification sent to current account*/
func (session *ESNSession) CountNotification(from int, to int) (int, error) {
	token := randToken()
	var pack PackCount
	pack.From = from
	pack.To = to
	pack.Token = token
	_, err := WritePackage(*session.Conn, pack, 11, "")
	if err != nil {
		return -1, err
	}
	result := &PackResult{}
	session.selectPack(token, result)

	if result.Error != "" {
		return -1, errors.New(result.Error)
	}

	count := &PackRespCount{}
	session.selectPack(token+"-1", count)

	return count.Amount, nil
}

func (session *ESNSession) RequestNotification(from int, to int, limit int) error {
	token := randToken()
	var pack PackRequest
	pack.From = from
	pack.To = to
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

/*Request recent notification*/
func (session *ESNSession) RequestRecent(limit int) error {
	token := randToken()
	var pack PackReqRecent
	pack.Limit = limit
	pack.Token = token

	_, err := WritePackage(*session.Conn, pack, 10, "")
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

/*Push one notification*/
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
