package hydra

func DefaultMongodbList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"admin",
		"test",
		"root",
		//"user",
		//"root",
		//"manager",
		//"webadmin",
	}
	a.Password = []string{
		"123456", "admin", "admin123", "root", "", "pass123", "pass@123", "password", "Password", "P@ssword123", "123123", "654321", "111111", "123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123", "{user}#123", "{user}@111", "{user}@2019", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe", "123qwe!@#", "123456789", "123321", "666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123", "Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456", "1q2w3e", "Charge123", "Aa123456789", "elastic123",
	}
	a.Special = []Auth{
		NewSpecialAuth("", ""),
		NewSpecialAuth("simpleUser", "simplePass"),
		NewSpecialAuth("adminUser", "adminPass"),
	}
	return a
}
