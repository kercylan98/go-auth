package auth

import (
	"fmt"
	"sync"
)

// Consumer 消费者模型定义
type Consumer interface {
	// GetTag 获取完整消费者标记
	GetTag() string
	// GetUsername 获取用户名标记
	GetUsername() string
	// GetToken 获取消费者token
	GetToken() (string, error)
	// CheckToken 验证消费者token是否合法
	CheckToken(token string) bool
	// GetAllRole 获取消费者所有角色
	GetAllRole() []Role
	// RoleExist 检查消费者是否拥有特定角色
	RoleExist(roleName ...string) bool
	// ResourceExist 检查消费者是否存在特定资源权限
	ResourceExist(resourceUri ...string) bool
	// Store 存储数据到该消费者
	Store(key string, value interface{}) error
	// Load 加载存储到数据
	Load(key string) (interface{}, error)
	// Del 删除已存储到数据
	Del(key string) error
	// OutLogin 退出登录
	OutLogin() error

	// 获取消费者的客户端标记
	getClientTag() string
	// 赋予消费者新的角色组
	setRole(role ...Role)
}

func newConsumer(auth Auth, tag string, clientTag string) *consumer {
	return &consumer{
		auth:      auth,
		Tag:       tag,
		ClientTag: clientTag,
		FullTag:   tag + clientTag,
		Roles:     []Role{},
	}
}

type consumer struct {
	sync.Mutex // 只有setRole会发生写操作，避免验证权限时改写，将其进行加锁
	auth       Auth
	Tag        string // 消费者标记，可以是用户名等具有唯一性等内容。
	ClientTag  string // 包含客户端标记的消费标记
	FullTag    string // 完整到标签
	Roles      []Role // 消费者拥有的角色
}

func (slf *consumer) RoleExist(roleName ...string) bool {
	var count = 0
	var match = len(roleName)
	for _, r := range slf.Roles {
		for _, s := range roleName {
			if r.GetName() == s {
				count++
				if count == match {
					return true
				}
			}
		}
	}
	return false
}

func (slf *consumer) Store(key string, value interface{}) error {
	session, err := slf.auth.getSession(slf)
	if err != nil {
		return err
	}
	return session.Store(key, value)
}

func (slf *consumer) Load(key string) (interface{}, error) {
	session, err := slf.auth.getSession(slf)
	if err != nil {
		return nil, err
	}

	return session.Load(key)
}

func (slf *consumer) Del(key string) error {
	session, err := slf.auth.getSession(slf)
	if err != nil {
		return err
	}
	return session.Del(key)
}

func (slf *consumer) GetAllRole() []Role {
	var roles []Role
	for _, r := range slf.Roles {
		roles = append(roles, r)
	}
	return roles
}

func (slf *consumer) ResourceExist(resourceUri ...string) bool {
	for _, r := range slf.Roles {
		if r.Exist(resourceUri...) {
			return true
		}
	}
	return false
}

func (slf *consumer) setRole(roles ...Role) {
	slf.Lock()
	slf.Roles = roles
	slf.Unlock()
}

func (slf *consumer) GetUsername() string {
	return slf.Tag
}

func (slf *consumer) getClientTag() string {
	return slf.ClientTag
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

func (slf *consumer) OutLogin() error {
	return slf.auth.Ban(slf)
}

func (slf *consumer) GetTag() string {
	return slf.FullTag
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
