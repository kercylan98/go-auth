package auth

import (
	"testing"
)

func TestNew(t *testing.T) {
	_, err := New()
	if err != nil {
		t.Fatal(err)
	}

}

func TestAuth_Login(t *testing.T) {
	auth, err := New()
	if err != nil {
		t.Fatal(err)
	}

	var (
		username = "admin"
		password = "12345"
	)

	t.Log("无该账号：")
	t.Log(auth.Login().Password(username, password))
	t.Log()

	auth.AddTempAccount(username, password)

	t.Log("密码错误")
	t.Log(auth.Login().Password(username, password + " "))
	t.Log()
	t.Log("成功登录")
	t.Log(auth.Login().Password(username, password))
	t.Log()
	t.Log("无需校验")
	t.Log(auth.Login().UsePasswordChecker(func(username string, password string) error {
		return nil
	}).Password(username, password + " "))
	t.Log()


}
