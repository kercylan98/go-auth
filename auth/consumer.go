package auth

import (
	"fmt"
	"sync"
)

// 消费者模型定义
type Consumer interface {
	// 获取完整消费者标记
	GetTag() string
	// 获取用户名标记
	GetUsername() string
	// 获取消费者token
	GetToken() (string, error)
	// 验证消费者token是否合法
	CheckToken(token string) bool
	// 获取消费者所有角色
	GetAllRole() []Role
	// 检查消费者是否存在特定资源权限
	ResourceExist(resourceUri string) bool
	// 退出登录
	OutLogin()

	// 获取消费者的客户端标记
	getClientTag() string
	// 赋予消费者新的角色组
	setRole(role ...Role)
}

func newConsumer(auth Auth, tag string, clientTag string) *consumer {
	return &consumer{
		auth:      auth,
		tag:       tag,
		clientTag: clientTag,
		fullTag:   tag + clientTag,
		roles:     []Role{},
	}
}

type consumer struct {
	sync.Mutex // 只有setRole会发生写操作，避免验证权限时改写，将其进行加锁
	auth       Auth
	tag        string // 消费者标记，可以是用户名等具有唯一性等内容。
	clientTag  string // 包含客户端标记的消费标记
	fullTag    string // 完整到标签
	roles      []Role // 消费者拥有的角色
}

func (slf *consumer) GetAllRole() []Role {
	return slf.roles
}

func (slf *consumer) ResourceExist(resourceUri string) bool {
	for _, r := range slf.roles {
		if r.Exist(resourceUri) {
			return true
		}
	}
	return false
}

func (slf *consumer) setRole(role ...Role) {
	slf.Lock()
	slf.roles = role
	slf.Unlock()
}

func (slf *consumer) GetUsername() string {
	return slf.tag
}

func (slf *consumer) getClientTag() string {
	return slf.clientTag
}

func (slf *consumer) CheckToken(token string) bool {
	var (
		err       error
		slfToken  string
		slfSource []byte
		check     []byte
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
	} else {
		if token, err := s.Load("token"); err != nil {
			return "", err
		} else {
			return token.(string), nil
		}
	}
}
