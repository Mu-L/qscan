package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func ActiveMQScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)
	fmt.Println("尝试默认账户 admin:admin")

	// 首先测试默认账户
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			fmt.Printf("第%d次重试默认账户", retryCount+1)
		}

		flag, err := ActiveMQConn(info, "admin", "admin")
		if flag {
			successMsg := fmt.Sprintf("ActiveMQ服务 %s 成功爆破 用户名: admin 密码: admin", target)
			fmt.Println(successMsg)

			// 保存结果
			m := make(map[string]string)
			sourceMap := misc.CloneMap(m)
			if jw := app.Setting.OutputJson; jw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "vulnerable"
				sourceMap["port"] = info.Ports
				sourceMap["service"] = "activemq"
				sourceMap["username"] = "admin"
				sourceMap["password"] = "admin"
				sourceMap["type"] = "weak-password"
				jw.Push(sourceMap)
			}
			if cw := app.Setting.OutputCSV; cw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "vulnerable"
				sourceMap["port"] = info.Ports
				sourceMap["service"] = "activemq"
				sourceMap["username"] = "admin"
				sourceMap["password"] = "admin"
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
		if err != nil {
			errMsg := fmt.Sprintf("ActiveMQ服务 %s 默认账户尝试失败: %v", target, err)
			fmt.Println(errMsg)

			if retryErr := app.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	totalUsers := len(app.Userdict["activemq"])
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass)

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range app.Userdict["activemq"] {
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
					flag, err := ActiveMQConn(info, user, pass)
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
					if result.success {
						successMsg := fmt.Sprintf("ActiveMQ服务 %s 成功爆破 用户名: %v 密码: %v", target, user, pass)
						fmt.Println(successMsg)

						// 保存结果
						m := make(map[string]string)
						sourceMap := misc.CloneMap(m)
						if jw := app.Setting.OutputJson; jw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "vulnerable"
							sourceMap["port"] = info.Ports
							sourceMap["service"] = "activemq"
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
							sourceMap["service"] = "activemq"
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
					errMsg := fmt.Sprintf("ActiveMQ服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v", target, user, pass, err)
					fmt.Println(errMsg)

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

// ActiveMQConn 统一的连接测试函数
func ActiveMQConn(info *app.HostInfo, user string, pass string) (bool, error) {
	timeout := time.Duration(3) * time.Second
	addr := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// STOMP协议的CONNECT命令
	stompConnect := fmt.Sprintf("CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\nlogin:%s\npasscode:%s\n\n\x00", user, pass)

	// 发送认证请求
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(stompConnect)); err != nil {
		return false, err
	}

	// 读取响应
	conn.SetReadDeadline(time.Now().Add(timeout))
	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil {
		return false, err
	}

	// 检查认证结果
	response := string(respBuf[:n])

	if strings.Contains(response, "CONNECTED") {
		return true, nil
	}

	if strings.Contains(response, "Authentication failed") || strings.Contains(response, "ERROR") {
		return false, fmt.Errorf("认证失败")
	}

	return false, fmt.Errorf("未知响应: %s", response)
}
