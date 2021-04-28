package auth

// 资源组
type ResourceGroup interface {
	// 获取资源组名称
	GetName() string
	// 获取资源数量
	GetResourceCount() int
	// 获取所有资源
	GetAllResource() []Resource
	// 添加资源
	Add(resource ...Resource) ResourceGroup
	// 资源是否存在
	Exist(resourceUri string) bool
	// 通过uri获取资源
	GetResource(uri string) Resource
}

func newResourceGroup(name string) *resourceGroup {
	return &resourceGroup{
		Name:      name,
		Resources: []Resource{},
		Mapper:    map[string]int{},
	}
}

type resourceGroup struct {
	Name      string         // 资源组名称
	Resources []Resource     // 所有资源
	Mapper    map[string]int // 资源映射判定是否重复 (Uri:index)
}

func (slf *resourceGroup) GetResource(uri string) Resource {
	return slf.Resources[slf.Mapper[uri]]
}

func (slf *resourceGroup) GetName() string {
	return slf.Name
}

func (slf *resourceGroup) GetResourceCount() int {
	return len(slf.Resources)
}

func (slf *resourceGroup) GetAllResource() []Resource {
	return slf.Resources
}

func (slf *resourceGroup) Exist(resourceUri string) bool {
	_, exist := slf.Mapper[resourceUri]
	return exist
}

func (slf *resourceGroup) Add(resource ...Resource) ResourceGroup {
	for _, r := range resource {
		if slf.Exist(r.GetURI()) {
			continue
		}
		slf.Mapper[r.GetURI()] = len(slf.Resources)
		slf.Resources = append(slf.Resources, r)
	}
	return slf
}
