package hydra

func DefaultFtpList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"anonymous",
		"ftp",
		"test",
		"admin",
		"www",
		"web",
		"root",
		"db",
		"wwwroot",
		"data",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("anonymous", "anonymous"),
		NewSpecialAuth("ftp", "ftp"),
		NewSpecialAuth("admin", "admin"),
		NewSpecialAuth("admin", "123456"),
	}
	return a
}
