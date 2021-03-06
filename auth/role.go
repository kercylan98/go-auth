package auth

// Role 角色接口
type Role interface {
	// GetName 获取角色名称
	GetName() string
	// GetAllResourceGroup 获取所有资源组
	GetAllResourceGroup() []ResourceGroup
	// GetAllResource 获取所有资源
	GetAllResource() []Resource
	// Exist 角色是否同时拥有多条资源
	Exist(resourceUri ...string) bool
	// AddResourceGroup 添加资源组
	AddResourceGroup(resourceGroup ...ResourceGroup) Role
}

func newRole(name string) *role {
	return &role{
		Name:           name,
		ResourceGroups: []ResourceGroup{},
	}
}

type role struct {
	Name           string          // 角色名称
	ResourceGroups []ResourceGroup // 角色拥有对资源组
}

func (slf *role) Exist(resourceUri ...string) bool {
	var count = 0
	var match = len(resourceUri)
	for _, group := range slf.ResourceGroups {
		for _, s := range resourceUri {
			if group.Exist(s) {
				count++
				if count == match {
					return true
				}
			}
		}
	}
	return false
}

func (slf *role) GetName() string {
	return slf.Name
}

func (slf *role) GetAllResourceGroup() []ResourceGroup {
	return slf.ResourceGroups
}

func (slf *role) GetAllResource() []Resource {
	var resources []Resource
	for _, group := range slf.ResourceGroups {
		resources = append(resources, group.GetAllResource()...)
	}
	return resources
}

func (slf *role) AddResourceGroup(resourceGroup ...ResourceGroup) Role {
	slf.ResourceGroups = append(slf.ResourceGroups, resourceGroup...)
	return slf
}
