package Plugins

import (
	"Qscan/app"
	"Qscan/lib/misc"
	"fmt"
	"github.com/gocql/gocql"
	"github.com/lcvvvv/stdio/chinese"
	"strconv"
	"strings"
	"time"
)

func CassandraScan(info *app.HostInfo) (tmperr error) {

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	maxRetries := 3

	fmt.Printf("开始扫描 %s", target)
	fmt.Printf("尝试无认证访问...")

	// 首先测试无认证访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			fmt.Printf("第%d次重试无认证访问", retryCount+1)
		}

		flag, err := CassandraConn(info, "", "")
		if flag && err == nil {
			successMsg := fmt.Sprintf("Cassandra服务 %s 无认证访问成功", target)
			fmt.Printf(successMsg)

			// 保存无认证访问结果
			m := make(map[string]string)
			sourceMap := misc.CloneMap(m)
			if jw := app.Setting.OutputJson; jw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "vulnerable"
				sourceMap["port"] = info.Ports
				sourceMap["service"] = "cassandra"
				sourceMap["type"] = "unauthorized-access"
				sourceMap["description"] = "数据库允许无认证访问"
				jw.Push(sourceMap)
			}
			if cw := app.Setting.OutputCSV; cw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "vulnerable"
				sourceMap["port"] = info.Ports
				sourceMap["service"] = "cassandra"
				sourceMap["type"] = "unauthorized-access"
				sourceMap["description"] = "数据库允许无认证访问"
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
			return err
		}
		if err != nil && app.CheckErrs(err) != nil {
			if retryCount == maxRetries-1 {
				return err
			}
			continue
		}
		break
	}

	totalUsers := len(app.Userdict["cassandra"])
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass)

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range app.Userdict["cassandra"] {
		for _, pass := range app.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			fmt.Printf("[%d/%d] 尝试: %s:%s", tried, total, user, pass)

			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					fmt.Printf("第%d次重试: %s:%s", retryCount+1, user, pass)
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := CassandraConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						successMsg := fmt.Sprintf("Cassandra服务 %s 爆破成功 用户名: %v 密码: %v", target, user, pass)
						fmt.Printf(successMsg)

						// 保存爆破成功结果
						m := make(map[string]string)
						sourceMap := misc.CloneMap(m)
						if jw := app.Setting.OutputJson; jw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "vulnerable"
							sourceMap["port"] = info.Ports
							sourceMap["service"] = "cassandra"
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
							sourceMap["service"] = "cassandra"
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
					errlog := fmt.Sprintf("Cassandra服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v", target, user, pass, err)
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

// CassandraConn 清理后的连接测试函数
func CassandraConn(info *app.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second

	cluster := gocql.NewCluster(host)
	cluster.Port, _ = strconv.Atoi(port)
	cluster.Timeout = timeout
	cluster.ProtoVersion = 4
	cluster.Consistency = gocql.One

	if user != "" || pass != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: pass,
		}
	}

	cluster.RetryPolicy = &gocql.SimpleRetryPolicy{NumRetries: 3}

	session, err := cluster.CreateSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	var version string
	if err := session.Query("SELECT peer FROM system.peers").Scan(&version); err != nil {
		if err := session.Query("SELECT now() FROM system.local").Scan(&version); err != nil {
			return false, err
		}
	}

	return true, nil
}
