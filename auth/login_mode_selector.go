package auth

import (
	"errors"
)

// LoginModeSelector 登录模式选择器
type LoginModeSelector interface {
	// Password 密码登录（也可用于密钥等）
	Password(username string, password string) (Consumer, error)
	// UsePasswordChecker 使用验证器（可多个），不使用的情况下，则在内存中进行验证
	UsePasswordChecker(checker ...func(username string, password string) error) LoginModeSelector
}

func newLoginModeSelector(auth Auth) LoginModeSelector {
	return &loginModeSelector{
		auth:            auth,
		passwordChecker: nil,
	}
}

type loginModeSelector struct {
	auth            Auth
	passwordChecker []func(username string, password string) error
}

func (slf *loginModeSelector) UsePasswordChecker(checker ...func(username string, password string) error) LoginModeSelector {
	slf.passwordChecker = checker
	return slf
}

func (slf *loginModeSelector) Password(username string, password string) (Consumer, error) {
	if slf.passwordChecker != nil {
		for _, f := range slf.passwordChecker {
			if err := f(username, password); err != nil {
				return nil, err
			}
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
