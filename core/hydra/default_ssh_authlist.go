package hydra

func DefaultSshList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"root",
		"admin",
		//"test",
		//"user",
		//"root",
		//"manager",
		//"webadmin",
	}
	a.Password = append([]string{}, DefaultCommonPasswords...)
	a.Special = []Auth{
		NewSpecialAuth("db2admin", "db2admin"),
		NewSpecialAuth("oracle", "oracle"),
		NewSpecialAuth("mysql", "mysql"),
		NewSpecialAuth("postgres", "postgres"),
		NewSpecialAuth("kali", "kali"),
		NewSpecialAuth("defaultUsername", "defaultPassword"),
		NewSpecialAuth("admin", "Admin@huawei"),
		NewSpecialAuth("admin", "admin@huawei.com"),
		NewSpecialAuth("admin", "admin"),
		NewSpecialAuth("admin", "Admin@123"),
		NewSpecialAuth("admin", "Changeme_123"),
		NewSpecialAuth("admin", "Admin123"),
		NewSpecialAuth("admin", "Changeme123"),
		NewSpecialAuth("admin", "Admin@storage"),
		NewSpecialAuth("admin", "eSight@123"),
		NewSpecialAuth("admin", "Cis#BigData123"),
		NewSpecialAuth("admin", "Huawei@123"),
		NewSpecialAuth("LogAdmin", "Changeme123"),
		NewSpecialAuth("SystemAdmin", "Changeme123"),
		NewSpecialAuth("OperateAdmin", "Changeme123"),
		NewSpecialAuth("administrator", "Changeme123"),
		NewSpecialAuth("Administrator", "Admin@9000"),
		NewSpecialAuth("Administrator", "Changeme@321"),
		NewSpecialAuth("api-admin", "admin@123"),
		NewSpecialAuth("root", "admin123"),
		NewSpecialAuth("root", "mduadmin"),
		NewSpecialAuth("root", "Changeme_123"),
		NewSpecialAuth("root", "admin"),
		NewSpecialAuth("root", "adminHW"),
		NewSpecialAuth("root", "password"),
		NewSpecialAuth("root", "Huawei12#$"),
		NewSpecialAuth("root", "Changeme@321"),
		NewSpecialAuth("root", "Changeme123"),
		NewSpecialAuth("sa", "Changeme123"),
		NewSpecialAuth("db2inst1", "db2inst1"),
		NewSpecialAuth("db2fenc1", "db2fenc1"),
		NewSpecialAuth("dasusr1", "dasusr1"),
		NewSpecialAuth("db2admin", "db2admin"),
	}
	return a
}
