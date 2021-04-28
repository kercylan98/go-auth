package auth

import (
	"encoding/json"
	"fmt"
	"github.com/kercylan98/kkit-core/crypto"
	"github.com/kercylan98/kkit-session/session"
	"sync"
	"time"
)

type Auth interface {
	// 消费者登录
	Login() LoginModeSelector
	// 检查消费者是否登录
	IsLogin(consumer Consumer) bool
	// 根据token检查消费者是否登录
	IsLoginWithToken(token string) bool
	// 获取消费者
	GetConsumer(tag string) (Consumer, error)
	// 通过Token获取消费者
	GetConsumerWithToken(token string) (Consumer, error)
	// 获取所有消费者
	GetAllConsumer() []Consumer
	// 踢出消费者
	Ban(consumer Consumer) error
	// 设置消费者登录凭证过期时间
	SetExpired(expired time.Duration) error
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

func New(manager session.Manager) (Auth, error) {
	auth := &auth{
		tempAccount: map[string]string{},
		sm:          manager,
		rsa:         &crypto.Rsa{},

		allowManyClient: false,
	}
	if err := auth.rsa.GenRsaKey(1024); err != nil {
		return nil, err
	}
	return auth, nil
}

type auth struct {
	sync.Mutex                    // 备用互斥锁，sm本身支持并发操作。
	tempAccount map[string]string // 临时的内存存储的用户账号密码集合
	sm          session.Manager   // 会话管理器（支持并发）
	rsa         *crypto.Rsa       // rsa加密

	allowManyClient bool          // 是否允许多端登录，如果不允许。将会一方登入，另一方掉线
	clientTagFunc   func() string // 客户端标记获取函数

	roleSetter func(username string, roleHelper *RoleHelper) ([]Role, error) // 消费者资源查询函数
}

func (slf *auth) IsLoginWithToken(token string) bool {
	tag, err := slf.rsa.RsaDecrypt([]byte(token))
	if err != nil {
		return false
	}
	_, err = slf.GetConsumer(string(tag))
	return err == nil
}

func (slf *auth) IsLogin(consumer Consumer) bool {
	_, err := slf.GetConsumer(consumer.GetTag())
	return err == nil
}

func (slf *auth) GetConsumerWithToken(token string) (Consumer, error) {
	tag, err := slf.rsa.RsaDecrypt([]byte(token))
	if err != nil {
		return nil, err
	}
	return slf.GetConsumer(string(tag))
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
		if c.GetUsername() == consumer.GetUsername() && (c.getClientTag() != consumer.getClientTag()) {
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
		fmt.Println("set allow many client login failed, not found client Tag getter.")
		return
	}
	slf.allowManyClient = true
	slf.clientTagFunc = clientTag
}

func (slf *auth) SetExpired(expired time.Duration) error {
	return slf.sm.SetExpire(expired)
}

func (slf *auth) getSession(consumer Consumer) (session.Session, error) {
	return slf.sm.GetSession(consumer.GetTag())
}

func (slf *auth) GetAllConsumer() []Consumer {
	var cs []Consumer
	allSession, err := slf.sm.GetAllSession()
	if err != nil {
		return cs
	}
	for _, s := range allSession {
		c, err := s.Load(s.GetId())
		if err == nil {
			switch c.(type) {
			case Consumer:
				cs = append(cs, c.(Consumer))
			default:
				c, err := slf.jsonToConsumer(c)
				if err != nil {
					continue
				}
				cs = append(cs, c)
			}
		}
	}
	return cs
}

func (slf *auth) Ban(consumer Consumer) error {
	if s, err := slf.getSession(consumer); err == nil {
		return slf.sm.UnRegisterSession(s)
	}
	return nil
}

func (slf *auth) GetConsumer(tag string) (Consumer, error) {
	s, err := slf.sm.GetSession(tag)
	if err != nil {
		return nil, err
	}
	c, err := s.Load(tag)
	if err == nil {
		switch c.(type) {
		case Consumer:
			return c.(Consumer), nil
		default:
			return slf.jsonToConsumer(c)
		}
	}
	return nil, err
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

		ses, err = slf.sm.RegisterSession(consumerTag)
		if err != nil {
			return err
		}
		err = ses.Store(consumerTag, consumer)
		if err != nil {
			return err
		}
		err = ses.Store("token", token)
		if err != nil {
			return err
		}
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
			err = ses.Store("token", token)
			if err != nil {
				return err
			}
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

func (slf *auth) jsonToConsumer(redisConsumerInterface interface{}) (Consumer, error) {
	// 完整消费者信息
	cMap := redisConsumerInterface.(map[string]interface{})
	// 提取角色信息
	roleInfo := cMap["Roles"]
	roleInfoJson, err := json.Marshal(roleInfo)
	if err != nil {
		return nil, err
	}
	// 转化到角色信息模型
	roleInfoModel := new(roleModel)
	err = json.Unmarshal(roleInfoJson, roleInfoModel)
	if err != nil {
		return nil, err
	}

	delete(cMap, "Roles")

	jd, err := json.Marshal(redisConsumerInterface)
	if err != nil {
		return nil, err
	}
	var formatC = new(consumer)
	err = json.Unmarshal(jd, formatC)
	if err != nil {
		return nil, err
	}
	formatC.auth = slf
	formatC.Roles = roleInfoModel.toRoles()
	return formatC, nil
}
