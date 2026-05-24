package hydra

func DefaultPostgresqlList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"postgres",
		"test",
		"admin",
		//"user",
		//"root",
		//"manager",
		//"webadmin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{}
	return a
}
