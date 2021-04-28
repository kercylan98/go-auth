package auth

// 权限资源接口
type Resource interface {
	// 获取资源名称
	GetName() string
	// 获取资源URI
	GetURI() string
}

func newResource(name string, uri string) *resource {
	return &resource{
		Name: name,
		Uri:  uri,
	}
}

type resource struct {
	Name string // 资源名称
	Uri  string // Uri
}

func (slf *resource) GetName() string {
	return slf.Name
}

func (slf *resource) GetURI() string {
	return slf.Uri
}
