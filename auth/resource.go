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
		name: name,
		uri:  uri,
	}
}

type resource struct {
	name string // 资源名称
	uri  string // uri
}

func (slf *resource) GetName() string {
	return slf.name
}

func (slf *resource) GetURI() string {
	return slf.uri
}
