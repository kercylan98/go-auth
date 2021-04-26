package auth

import (
	"errors"
)

// http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html
type LoginModeSelector interface {
	// 密码登录（也可用于密钥等）
	Password(username string, password string) (Consumer, error)
	// 使用验证器，不使用的情况下，则在内存中进行验证
	UsePasswordChecker(checker func(username string, password string) error) LoginModeSelector
}

func newLoginModeSelector(auth Auth) LoginModeSelector {
	return &loginModeSelector{
		auth:            auth,
		passwordChecker: nil,
	}
}

type loginModeSelector struct {
	auth            Auth
	passwordChecker func(username string, password string) error
}

func (slf *loginModeSelector) UsePasswordChecker(checker func(username string, password string) error) LoginModeSelector {
	slf.passwordChecker = checker
	return slf
}

func (slf *loginModeSelector) Password(username string, password string) (Consumer, error) {
	if slf.passwordChecker != nil {
		if err := slf.passwordChecker(username, password); err != nil {
			return nil, err
		}
		goto loginSuccess
	}
	if err := slf.tempLoginCheck(username, password); err != nil {
		return nil, err
	}

loginSuccess:
	{
		var tag = "__x_x__once"
		if slf.auth.getAllowManyClient() {
			tag = slf.auth.getAllowManyClientFunc()()
		}
		consumer := newConsumer(slf.auth, username, tag)
		if err := slf.auth.join(consumer); err != nil {
			return nil, err
		}
		return consumer, nil
	}
}

func (slf *loginModeSelector) tempLoginCheck(username string, password string) error {
	if p, exist := slf.auth.getTempAccount()[username]; exist {
		if p == password {
			return nil
		}
	}
	return errors.New("the account does not exist or the login password is wrong")
}
