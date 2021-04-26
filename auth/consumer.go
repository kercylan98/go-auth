package auth

import "fmt"

// 消费者模型定义
type Consumer interface {
	// 获取完整消费者标记
	GetTag() string
	// 获取消费者的客户端标记
	GetClientTag() string
	// 获取用户名标记
	GetUsernameTag() string
	// 获取消费者token
	GetToken() (string, error)
	// 验证消费者token是否合法
	CheckToken(token string) bool
	// 退出登录
	OutLogin()
}


func newConsumer(auth Auth, tag string, clientTag string) *consumer {
	return &consumer{
		auth: auth,
		tag:  tag,
		clientTag: clientTag,
		fullTag: tag + clientTag,
	}
}

type consumer struct {
	auth Auth
	tag  string // 消费者标记，可以是用户名、token等具有唯一性等内容。
	clientTag string // 包含客户端标记的消费标记
	fullTag string
}

func (slf *consumer) GetUsernameTag() string {
	return slf.tag
}

func (slf *consumer) GetClientTag() string {
	return slf.clientTag
}

func (slf *consumer) CheckToken(token string) bool {
	var (
		err error
		slfToken string
		slfSource []byte
		check []byte
	)

	slfToken, err = slf.GetToken()
	if err != nil {
		fmt.Println("check token failed. err: ", err)
		return false
	}
	slfSource, err = slf.auth.getRsa().RsaDecrypt([]byte(slfToken))
	if err != nil {
		fmt.Println("check token failed. err: ", err)
		return false
	}

	check, err = slf.auth.getRsa().RsaDecrypt([]byte(token))
	if err != nil {
		fmt.Println("check token failed. err: ", err)
		return false
	}

	return string(slfSource) == string(check)
}

func (slf *consumer) OutLogin() {
	slf.auth.Ban(slf)
}

func (slf *consumer) GetTag() string {
	return slf.fullTag
}

func (slf *consumer) GetToken() (string, error) {
	if s, err := slf.auth.getSession(slf); err != nil {
		return "", err
	}else {
		if token, err := s.Load("token"); err != nil {
			return "", err
		}else {
			return token.(string), nil
		}
	}
}

