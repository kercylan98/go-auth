package auth

import (
	"fmt"
	"github.com/kercylan98/kkit-core/crypto"
	"github.com/kercylan98/kkit-session/session"
	"sync"
	"time"
)

type Auth interface {
	// 消费者登录
	Login() LoginModeSelector
	// 获取消费者
	GetConsumer(tag string) (Consumer, error)
	// 获取所有消费者
	GetAllConsumer() []Consumer
	// 踢出消费者
	Ban(consumer Consumer)
	// 设置消费者登录凭证过期时间
	SetExpired(expired time.Duration)
	// 设置禁止多端登录
	SetUnAllowManyClient()
	// 设置允许多端登录(需要传入客户端标记获取函数，避免一端退出全端退出)
	SetAllowManyClient(clientTag func() string)
	// 添加临时账号
	AddTempAccount(username string, password string)
	// 获取特定消费者正在多端登录的其他消费者
	GetMultiConsumer(consumer Consumer) []Consumer
	// 设置角色资源设置函数，将可以检查特定消费者是否拥有特定资源对权限。该函数将返回一个刷新函数
	SetRoleCheck(roleSetter func(username string, roleHelper *RoleHelper) ([]Role, error))
	// 刷新特定消费者角色资源
	RefreshRole(consumer Consumer) error

	// 获取临时账号密码库
	getTempAccount() map[string]string
	// 加入消费者
	join(consumer Consumer) error
	// 获取消费者session
	getSession(consumer Consumer) (session.Session, error)
	// 获取rsa
	getRsa() *crypto.Rsa
	// 获取是否允许多端登录
	getAllowManyClient() bool
	// 获取客户端标记生成深航
	getAllowManyClientFunc() func() string
}

func New() (Auth, error) {
	auth := &auth{
		tempAccount: map[string]string{},
		sm:          session.NewManager(),
		rsa:         &crypto.Rsa{},

		allowManyClient: false,
	}
	if err := auth.rsa.GenRsaKey(1024); err != nil {
		return nil, err
	}
	return auth, nil
}

type auth struct {
	sync.Mutex
	tempAccount map[string]string // 临时的内存存储的用户账号密码集合
	sm          session.Manager   // 会话管理器
	rsa         *crypto.Rsa       // rsa加密

	allowManyClient bool          // 是否允许多端登录，如果不允许。将会一方登入，另一方掉线
	clientTagFunc   func() string // 客户端标记获取函数

	roleSetter func(username string, roleHelper *RoleHelper) ([]Role, error) // 消费者资源查询函数
}

func (slf *auth) RefreshRole(consumer Consumer) error {
	if slf.roleSetter != nil {
		roles, err := slf.roleSetter(consumer.GetUsername(), &RoleHelper{})
		if err != nil {
			return err
		}
		consumer.setRole(roles...)
	}
	return nil
}

func (slf *auth) SetRoleCheck(roleSetter func(username string, roleHelper *RoleHelper) ([]Role, error)) {
	// 退出所有账号
	slf.Lock()
	for _, c := range slf.GetAllConsumer() {
		c.OutLogin()
	}
	slf.allowManyClient = false
	slf.roleSetter = roleSetter
	slf.Unlock()
}

func (slf *auth) GetMultiConsumer(consumer Consumer) []Consumer {
	var target []Consumer
	for _, c := range slf.GetAllConsumer() {
		if c.GetUsername() == consumer.GetUsername() && (c.GetClientTag() != consumer.GetClientTag()) {
			target = append(target, c)
		}
	}
	return target
}

func (slf *auth) getAllowManyClientFunc() func() string {
	return slf.clientTagFunc
}

func (slf *auth) getAllowManyClient() bool {
	return slf.allowManyClient
}

func (slf *auth) getRsa() *crypto.Rsa {
	return slf.rsa
}

func (slf *auth) AddTempAccount(username string, password string) {
	slf.tempAccount[username] = password
}

func (slf *auth) SetUnAllowManyClient() {
	// 退出所有账号
	slf.Lock()
	for _, c := range slf.GetAllConsumer() {
		c.OutLogin()
	}
	slf.allowManyClient = false
	slf.Unlock()
}

func (slf *auth) SetAllowManyClient(clientTag func() string) {
	if clientTag == nil {
		fmt.Println("set allow many client login failed, not found client tag getter.")
		return
	}
	slf.allowManyClient = true
	slf.clientTagFunc = clientTag
}

func (slf *auth) SetExpired(expired time.Duration) {
	slf.sm.SetExpire(expired)
}

func (slf *auth) getSession(consumer Consumer) (session.Session, error) {
	return slf.sm.GetSession(consumer.GetTag())
}

func (slf *auth) GetAllConsumer() []Consumer {
	var cs []Consumer
	for _, s := range slf.sm.GetAllSession() {
		c, err := s.Load(s.GetId())
		if err == nil {
			cs = append(cs, c.(Consumer))
		}
	}
	return cs
}

func (slf *auth) Ban(consumer Consumer) {
	if s, err := slf.getSession(consumer); err == nil {
		slf.sm.UnRegisterSession(s)
	}
}

func (slf *auth) GetConsumer(tag string) (Consumer, error) {
	s, err := slf.sm.GetSession(tag)
	if err != nil {
		return nil, err
	}
	c, err := s.Load(tag)
	return c.(Consumer), err
}

func (slf *auth) Login() LoginModeSelector {
	return newLoginModeSelector(slf)
}

func (slf *auth) getTempAccount() map[string]string {
	return slf.tempAccount
}

func (slf *auth) join(consumer Consumer) error {
	// 检查是否已登录，避免重复登录
	consumerTag := consumer.GetTag()
	if ses, err := slf.sm.GetSession(consumerTag); err != nil {
		err = slf.RefreshRole(consumer)
		if err != nil {
			return err
		}
		token, err := slf.newToken(consumerTag)
		if err != nil {
			return err
		}

		ses = slf.sm.RegisterSession(consumerTag)
		ses.Store(consumerTag, consumer)
		ses.Store("token", token)
	} else {
		// 如果禁止多端登录，那么凭证将会使用不同的，并在登录前踢出其他凭证账号
		if !slf.allowManyClient {
			err = slf.RefreshRole(consumer)
			if err != nil {
				return err
			}
			token, err := slf.newToken(consumerTag)
			if err != nil {
				return err
			}
			// 刷新token
			ses.Store("token", token)
		}
	}

	return nil
}

func (slf *auth) newToken(tag string) (string, error) {
	// 生成token
	token, err := slf.rsa.RsaEncrypt([]byte(tag))
	if err != nil {
		return "", err
	}
	return string(token), nil
}
