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

	t.Log("密码错误：")
	t.Log(auth.Login().Password(username, password+" "))
	t.Log()
	t.Log("成功登录：")
	t.Log(auth.Login().Password(username, password))
	t.Log()
	t.Log("自定义校验逻辑：")
	t.Log(auth.Login().UsePasswordChecker(func(username string, password string) error {
		return nil
	}).Password(username, password+" "))
	t.Log()

}

func TestAuth_SetRoleCheck(t *testing.T) {
	auth, err := New()
	if err != nil {
		t.Fatal(err)
	}
	var (
		username = "admin"
		password = "12345"
	)
	auth.AddTempAccount(username, password)

	consumer, err := auth.Login().Password(username, password)
	if err != nil {
		t.Fatal(err)
	}

	// 设置权限校验，重置登录状态
	auth.SetRoleCheck(func(username string, roleHelper *RoleHelper) ([]Role, error) {
		return []Role{
			roleHelper.NewRole("test-role").
				AddResourceGroup(roleHelper.NewResourceGroup("test-group").
					Add(roleHelper.NewResource("test-resource", "/hi"))),
		}, nil
	})

	// 测试权限验证
	if consumer, err = auth.GetConsumer(consumer.GetTag()); err != nil {
		t.Log(err)
		consumer, err = auth.Login().Password(username, password)
		if err == nil {
			t.Log("check /hi", consumer.ResourceExist("/hi"))
			t.Log("check /hello", consumer.ResourceExist("/hello"))
		}
	}
}
