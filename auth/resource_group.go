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
		name:      name,
		resources: []Resource{},
		mapper:    map[string]int{},
	}
}

type resourceGroup struct {
	name      string         // 资源组名称
	resources []Resource     // 所有资源
	mapper    map[string]int // 资源映射判定是否重复 (uri:index)
}

func (slf *resourceGroup) GetResource(uri string) Resource {
	return slf.resources[slf.mapper[uri]]
}

func (slf *resourceGroup) GetName() string {
	return slf.name
}

func (slf *resourceGroup) GetResourceCount() int {
	return len(slf.resources)
}

func (slf *resourceGroup) GetAllResource() []Resource {
	return slf.resources
}

func (slf *resourceGroup) Exist(resourceUri string) bool {
	_, exist := slf.mapper[resourceUri]
	return exist
}

func (slf *resourceGroup) Add(resource ...Resource) ResourceGroup {
	for _, r := range resource {
		if slf.Exist(r.GetURI()) {
			continue
		}
		slf.mapper[r.GetURI()] = len(slf.resources)
		slf.resources = append(slf.resources, r)
	}
	return slf
}
