package auth

// 角色助手
type RoleHelper struct{}

// 创建一个角色
//
// 角色将拥有多个资源组对多条资源权限
func (slf *RoleHelper) NewRole(name string) Role {
	return newRole(name)
}

// 创建一个资源组
//
// 资源组可以对多条资源权限进行管理、分类
func (slf *RoleHelper) NewResourceGroup(name string) ResourceGroup {
	return newResourceGroup(name)
}

// 创建一条资源权限
//
// 拥有该条资源就表示拥有该权限
func (slf *RoleHelper) NewResource(name string, uri string) Resource {
	return newResource(name, uri)
}
