package auth

import (
	"fmt"
	"github.com/kercylan98/kkit-session/session"
	uuid "github.com/satori/go.uuid"
	"testing"
	"time"
)

func BenchmarkAuth_Simulated(b *testing.B) {
	b.StopTimer()
	auth, err := New(session.NewManagerRedis("localhost:6379"))
	if err != nil {
		b.Fatal(err)
	}
	// 设置权限校验，重置登录状态
	auth.SetRoleCheck(func(username string, roleHelper *RoleHelper) ([]Role, error) {
		return []Role{
			roleHelper.NewRole("test-role").
				AddResourceGroup(roleHelper.NewResourceGroup("test-group").
					Add(roleHelper.NewResource("test-resource", "/hi"))),
		}, nil
	})
	err = auth.SetExpired(10 * time.Second)
	if err != nil {
		b.Fatal(err)
	}
	auth.SetAllowManyClient(func() string {
		return uuid.NewV4().String()
	})

	b.N = 10       // 可以修改执行次数
	b.StartTimer() // 重新开始时间计时
	for i := 0; i < b.N; i++ {
		account := fmt.Sprint(uuid.NewV4())
		//account := fmt.Sprint(i)
		consumer, err := auth.Login().UsePasswordChecker(func(username string, password string) error {
			return nil
		}).Password(account, "123456")
		if err != nil {
			b.Fatal("error: ", err, "\n#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#")
		}
		b.Log("login success: ", account)
		b.Log("check resource: /hi, ", consumer.ResourceExist("/hi"))
		b.Log("check resource: /hello, ", consumer.ResourceExist("/hello"))
		b.Log("check role: admin, ", consumer.RoleExist("admin"))
		b.Log("check role: test-role, ", consumer.RoleExist("test-role"))
		b.Log("all consumer: ", fmt.Sprint(len(auth.GetAllConsumer())))

		err = consumer.OutLogin()
		if err != nil {
			b.Fatal("error: ", err, "\n#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#")
		} else {
			b.Log("out Login.")
		}
		b.Log("#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#")
	}
}

func TestRedisNew(t *testing.T) {
	_, err := New(session.NewManagerRedis("localhost:6379"))
	if err != nil {
		t.Fatal(err)
	}

}

func TestAuth_SetAllowManyClient(t *testing.T) {
	auth, err := New(session.NewManagerRedis("localhost:6379"))
	if err != nil {
		t.Fatal(err)
	}

	c, err := auth.GetConsumer("admin__x_x__once")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(c)
	auth.Ban(c)
}

func TestRedisAuth_Login(t *testing.T) {
	auth, err := New(session.NewManagerRedis("localhost:6379"))
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

func TestRedisAuth_SetRoleCheck(t *testing.T) {
	auth, err := New(session.NewManagerRedis("localhost:6379"))
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
