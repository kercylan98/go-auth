package auth

// 角色接口
type Role interface {
	// 获取角色名称
	GetName() string
	// 获取所有资源组
	GetAllResourceGroup() []ResourceGroup
	// 获取所有资源
	GetAllResource() []Resource
	// 角色是否同时拥有多条资源
	Exist(resourceUri ...string) bool
	// 添加资源组
	AddResourceGroup(resourceGroup ...ResourceGroup) Role
}

func newRole(name string) *role {
	return &role{
		name:           name,
		resourceGroups: []ResourceGroup{},
	}
}

type role struct {
	name           string          // 角色名称
	resourceGroups []ResourceGroup // 角色拥有对资源组
}

func (slf *role) Exist(resourceUri ...string) bool {
	var count = 0
	var match = len(resourceUri)
	for _, group := range slf.resourceGroups {
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
	return slf.name
}

func (slf *role) GetAllResourceGroup() []ResourceGroup {
	return slf.resourceGroups
}

func (slf *role) GetAllResource() []Resource {
	var resources []Resource
	for _, group := range slf.resourceGroups {
		resources = append(resources, group.GetAllResource()...)
	}
	return resources
}

func (slf *role) AddResourceGroup(resourceGroup ...ResourceGroup) Role {
	slf.resourceGroups = append(slf.resourceGroups, resourceGroup...)
	return slf
}
