package auth

type roleModel []struct {
	Name           string `json:"Name"`
	ResourceGroups []struct {
		Mapper    map[string]int `json:"Mapper"`
		Name      string         `json:"Name"`
		Resources []struct {
			Name string `json:"Name"`
			URI  string `json:"Uri"`
		} `json:"Resources"`
	} `json:"ResourceGroups"`
}

func (slf *roleModel) toRoles() []Role {
	var roles []Role
	for _, roleInfo := range *slf {
		role := new(role)
		role.Name = roleInfo.Name
		role.ResourceGroups = []ResourceGroup{}
		for _, resourceGroupInfo := range roleInfo.ResourceGroups {
			var resources []Resource
			for _, resourceInfo := range resourceGroupInfo.Resources {
				resources = append(resources, &resource{
					Name: resourceInfo.Name,
					Uri:  resourceInfo.URI,
				})
			}
			role.ResourceGroups = append(role.ResourceGroups, &resourceGroup{
				Name:      resourceGroupInfo.Name,
				Resources: resources,
				Mapper:    resourceGroupInfo.Mapper,
			})
		}
		roles = append(roles, role)
	}
	return roles
}
