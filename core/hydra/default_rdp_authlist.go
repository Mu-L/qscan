package hydra

func DefaultRdpList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"administrator",
		"admin",
		"test",
		"guest",
		//"user",
		//"root",
		//"manager",
		//"webadmin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("guest", "guest"),
		NewSpecialAuth("guest", "123456"),
		NewSpecialAuth("db2admin", "db2admin"),
	}
	return a
}
