package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"strconv"
	"strings"
	"time"
)

func Neo4jScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)

	// 首先测试无认证访问和默认凭证
	initialChecks := []struct {
		user string
		pass string
	}{
		{"", ""},           // 无认证
		{"neo4j", "neo4j"}, // 默认凭证
	}

	fmt.Println("尝试默认凭证...")
	for _, check := range initialChecks {
		fmt.Printf("尝试: %s:%s", check.user, check.pass)
		flag, err := Neo4jConn(info, check.user, check.pass)
		if flag && err == nil {
			var msg string
			if check.user == "" {
				msg = fmt.Sprintf("Neo4j服务 %s 无需认证即可访问", target)
				fmt.Printf(msg)

				// 保存结果 - 无认证访问
				m := make(map[string]string)
				sourceMap := misc.CloneMap(m)
				if jw := app.Setting.OutputJson; jw != nil {
					sourceMap["URL"] = info.Host
					sourceMap["Keyword"] = "CrackSuccess"
					sourceMap["Status"] = "vulnerable"
					sourceMap["port"] = info.Ports
					sourceMap["service"] = "neo4j"
					sourceMap["type"] = "unauthorized-access"
					jw.Push(sourceMap)
				}
				if cw := app.Setting.OutputCSV; cw != nil {
					sourceMap["URL"] = info.Host
					sourceMap["Keyword"] = "CrackSuccess"
					sourceMap["Status"] = "vulnerable"
					sourceMap["port"] = info.Ports
					sourceMap["service"] = "neo4j"
					sourceMap["type"] = "unauthorized-access"
					delete(sourceMap, "Header")
					delete(sourceMap, "Cert")
					delete(sourceMap, "Response")
					delete(sourceMap, "Body")
					sourceMap["Digest"] = strconv.Quote(sourceMap["Digest"])
					for key, value := range sourceMap {
						sourceMap[key] = chinese.ToUTF8(value)
					}
					cw.Push(sourceMap)
				}
			} else {
				msg = fmt.Sprintf("Neo4j服务 %s 默认凭证可用 用户名: %s 密码: %s", target, check.user, check.pass)
				fmt.Printf(msg)

				// 保存结果 - 默认凭证
				m := make(map[string]string)
				sourceMap := misc.CloneMap(m)
				if jw := app.Setting.OutputJson; jw != nil {
					sourceMap["URL"] = info.Host
					sourceMap["Keyword"] = "CrackSuccess"
					sourceMap["Status"] = "vulnerable"
					sourceMap["port"] = info.Ports
					sourceMap["service"] = "neo4j"
					sourceMap["username"] = check.user
					sourceMap["password"] = check.pass
					sourceMap["type"] = "default-credentials"
					jw.Push(sourceMap)
				}
				if cw := app.Setting.OutputCSV; cw != nil {
					sourceMap["URL"] = info.Host
					sourceMap["Keyword"] = "CrackSuccess"
					sourceMap["Status"] = "vulnerable"
					sourceMap["port"] = info.Ports
					sourceMap["service"] = "neo4j"
					sourceMap["username"] = check.user
					sourceMap["password"] = check.pass
					sourceMap["type"] = "default-credentials"
					delete(sourceMap, "Header")
					delete(sourceMap, "Cert")
					delete(sourceMap, "Response")
					delete(sourceMap, "Body")
					sourceMap["Digest"] = strconv.Quote(sourceMap["Digest"])
					for key, value := range sourceMap {
						sourceMap[key] = chinese.ToUTF8(value)
					}
					cw.Push(sourceMap)
				}
			}
			return err
		}
	}

	totalUsers := len(app.Userdict["neo4j"])
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass)

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range app.Userdict["neo4j"] {
		for _, pass := range app.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			fmt.Printf("[%d/%d] 尝试: %s:%s", tried, total, user, pass)

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					fmt.Printf("第%d次重试: %s:%s", retryCount+1, user, pass)
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := Neo4jConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						msg := fmt.Sprintf("Neo4j服务 %s 爆破成功 用户名: %s 密码: %s", target, user, pass)
						fmt.Printf(msg)

						// 保存结果 - 成功爆破
						m := make(map[string]string)
						sourceMap := misc.CloneMap(m)
						if jw := app.Setting.OutputJson; jw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "vulnerable"
							sourceMap["port"] = info.Ports
							sourceMap["service"] = "neo4j"
							sourceMap["username"] = user
							sourceMap["password"] = pass
							sourceMap["type"] = "weak-password"
							jw.Push(sourceMap)
						}
						if cw := app.Setting.OutputCSV; cw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "vulnerable"
							sourceMap["port"] = info.Ports
							sourceMap["service"] = "neo4j"
							sourceMap["username"] = user
							sourceMap["password"] = pass
							sourceMap["type"] = "weak-password"
							delete(sourceMap, "Header")
							delete(sourceMap, "Cert")
							delete(sourceMap, "Response")
							delete(sourceMap, "Body")
							sourceMap["Digest"] = strconv.Quote(sourceMap["Digest"])
							for key, value := range sourceMap {
								sourceMap[key] = chinese.ToUTF8(value)
							}
							cw.Push(sourceMap)
						}
						return nil
					}
				case <-time.After(time.Duration(3) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("Neo4j服务 %s 尝试失败 用户名: %s 密码: %s 错误: %v", target, user, pass, err)
					fmt.Printf(errlog)

					if retryErr := app.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue
					}
				}
				break
			}
		}
	}

	fmt.Printf("扫描完成，共尝试 %d 个组合", tried)
	return tmperr
}

// Neo4jConn 尝试 Neo4j 连接
func Neo4jConn(info *app.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second

	// 构造Neo4j URL
	uri := fmt.Sprintf("bolt://%s:%s", host, port)

	// 配置驱动选项
	config := func(c *neo4j.Config) {
		c.SocketConnectTimeout = timeout
	}

	var driver neo4j.Driver
	var err error

	// 尝试建立连接
	if user != "" || pass != "" {
		// 有认证信息时使用认证
		driver, err = neo4j.NewDriver(uri, neo4j.BasicAuth(user, pass, ""), config)
	} else {
		// 无认证时使用NoAuth
		driver, err = neo4j.NewDriver(uri, neo4j.NoAuth(), config)
	}

	if err != nil {
		return false, err
	}
	defer driver.Close()

	// 测试连接
	err = driver.VerifyConnectivity()
	if err != nil {
		return false, err
	}

	return true, nil
}
