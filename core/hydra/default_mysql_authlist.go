package hydra

func DefaultMysqlList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"root",
		"mysql",
		//"admin",
		//"test",
		//"user",
		//"root",
		//"manager",
		//"webadmin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("test", "test"),
		NewSpecialAuth("test", "123456"),
	}
	return a
}
