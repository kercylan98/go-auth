# kkit-auth

> 用于实现登录、鉴权的认证库

## 使用

### 认证器
```
auther, err := auth.New()
if err != nil {
	panic(err)
}

// 添加内置的账号密码
auther.AddTempAccount("admin", "123456")

// 使用内置的账号密码进行登录
// 返回登录后的消费者对象及错误信息（用户不存在或密码错误）
consumer, err := auther.Login().Password("admin", "123456")

// 使用自定义函数进行登录
// 返回登录后的消费者对象及错误信息（用户不存在或密码错误、自定义函数错误）
consumer, err = auther.Login().UsePasswordChecker(func(username string, password string) error {
	// todo: 数据库验证等...
	return nil
}).Password("admin", "123456")

// 刷新特定消费者角色资源权限信息(需配置后开启)
err = auther.RefreshRole(consumer)

// 根据用户标记查询用户（用户标记可通过token获得）
consumer, err = auther.GetConsumer(consumer.GetTag())

// 根据token查询用户
consumer, err = auther.GetConsumerWithToken(consumer.GetToken())

// 获取所有登录中的消费者
consumers := auther.GetAllConsumer()

// 获取特定消费者登录的其他客户端（需配置允许多端登录）
auther.GetMultiConsumer(consumer)

// 强制特定消费者下线
auther.Ban(consumer)
```

### 消费者
```
// 获取消费者标记（多端登录下也是唯一）
tag := consumer.GetTag()

// 获取登录时的用户名
username := consumer.GetUsername()

// 获取消费者Token
token := consumer.GetToken()

// 检测特定Token与消费者的Token是否匹配
consumer.CheckToken(token)

// 退出登录
consumer.OutLogin()

// 获取消费者的所有角色
consumer.GetAllRole()

// 检测消费者是否用于该uri的权限
consumer.ResourceExist("/api/project/create")
```
## 配置
```
// 设置登录失效时间（设置时将会为所有已登录消费者重置失效时间）
auther.SetExpired(30 *  time.Minute)

// 设置不允许多端登录（设置时将会登出所有消费者）
auther.SetUnAllowManyClient()

// 设置允许多端登录（需要返回一个客户端差异的字符串，如android、ios、chrome、safari等...）
auther.SetAllowManyClient(func() string {
	return time.Now().String()
})

// 启用角色权限认证（设置时将会登出所有消费者）
auther.SetRoleCheck(func(username string, roleHelper *auth.RoleHelper) ([]auth.Role, error) {
	// todo: 通过数据库根据username查询到角色权限信息后，采用roleHelper生成角色并返回，作为该username消费者的权限
	
	return []auth.Role{
		roleHelper.NewRole("admin").AddResourceGroup(
			roleHelper.NewResourceGroup("project").
				Add(roleHelper.NewResource("create", "/api/project/create")).
				Add(roleHelper.NewResource("get", "/api/project/get")).
				Add(roleHelper.NewResource("delete", "/api/project/delete")).
				Add(roleHelper.NewResource("update", "/api/project/update")),
			roleHelper.NewResourceGroup("user").
				Add(roleHelper.NewResource("create", "post:/api/user")).
				Add(roleHelper.NewResource("get", "get:/api/user")).
				Add(roleHelper.NewResource("delete", "delete:/api/user")).
				Add(roleHelper.NewResource("update", "put:/api/user")),
		),
		roleHelper.NewRole("administrator").AddResourceGroup(
			roleHelper.NewResourceGroup("project").
				Add(roleHelper.NewResource("create", "/api/project/create")).
				Add(roleHelper.NewResource("get", "/api/project/get")).
				Add(roleHelper.NewResource("delete", "/api/project/delete")).
				Add(roleHelper.NewResource("update", "/api/project/update")),
			roleHelper.NewResourceGroup("user").
				Add(roleHelper.NewResource("create", "post:/api/user")).
				Add(roleHelper.NewResource("get", "get:/api/user")).
				Add(roleHelper.NewResource("delete", "delete:/api/user")).
				Add(roleHelper.NewResource("update", "put:/api/user")),
		),
	}, nil

})
```