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

func RsyncScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)
	fmt.Println("尝试匿名访问...")

	// 首先测试匿名访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			fmt.Printf("第%d次重试匿名访问", retryCount+1)
		}

		flag, err := RsyncConn(info, "", "")
		if flag && err == nil {
			fmt.Printf("Rsync服务 %s 匿名访问成功", target)

			// 保存匿名访问结果

			m := make(map[string]string)
			sourceMap := misc.CloneMap(m)
			if jw := app.Setting.OutputJson; jw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "rsync"
				sourceMap["port"] = info.Ports
				sourceMap["type"] = "anonymous-access"
				jw.Push(sourceMap)
			}
			if cw := app.Setting.OutputCSV; cw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "rsync"
				sourceMap["port"] = info.Ports
				sourceMap["type"] = "anonymous-access"
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

		if err != nil {
			fmt.Printf("Rsync服务 %s 匿名访问失败: %v\n", target, err)
			if retryErr := app.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	totalUsers := len(app.Userdict["rsync"])
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass)

	tried := 0
	total := totalUsers * totalPass

	for _, user := range app.Userdict["rsync"] {
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
					flag, err := RsyncConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag && err == nil, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success {
						fmt.Printf("Rsync服务 %s 爆破成功 用户名: %v 密码: %v",
							target, user, pass)

						// 保存爆破成功结果
						m := make(map[string]string)
						sourceMap := misc.CloneMap(m)
						if jw := app.Setting.OutputJson; jw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "rsync"
							sourceMap["port"] = info.Ports
							sourceMap["username"] = user
							sourceMap["password"] = pass
							sourceMap["type"] = "weak-password"
							jw.Push(sourceMap)
						}
						if cw := app.Setting.OutputCSV; cw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "rsync"
							sourceMap["port"] = info.Ports
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
							return nil
						}
					}
				case <-time.After(time.Duration(3) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					fmt.Printf("Rsync服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v",
						target, user, pass, err)
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

func RsyncConn(info *app.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second

	// 建立连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	buffer := make([]byte, 1024)

	// 1. 读取服务器初始greeting
	n, err := conn.Read(buffer)
	if err != nil {
		return false, err
	}

	greeting := string(buffer[:n])
	if !strings.HasPrefix(greeting, "@RSYNCD:") {
		return false, fmt.Errorf("不是Rsync服务")
	}

	// 获取服务器版本号
	version := strings.TrimSpace(strings.TrimPrefix(greeting, "@RSYNCD:"))

	// 2. 回应相同的版本号
	_, err = conn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
	if err != nil {
		return false, err
	}

	// 3. 选择模块 - 先列出可用模块
	_, err = conn.Write([]byte("#list\n"))
	if err != nil {
		return false, err
	}

	// 4. 读取模块列表
	var moduleList strings.Builder
	for {
		n, err = conn.Read(buffer)
		if err != nil {
			break
		}
		chunk := string(buffer[:n])
		moduleList.WriteString(chunk)
		if strings.Contains(chunk, "@RSYNCD: EXIT") {
			break
		}
	}

	modules := strings.Split(moduleList.String(), "\n")
	for _, module := range modules {
		if strings.HasPrefix(module, "@RSYNCD") || module == "" {
			continue
		}

		// 获取模块名
		moduleName := strings.Fields(module)[0]

		// 5. 为每个模块创建新连接尝试认证
		authConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
		if err != nil {
			continue
		}
		defer authConn.Close()

		// 重复初始握手
		_, err = authConn.Read(buffer)
		if err != nil {
			authConn.Close()
			continue
		}

		_, err = authConn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
		if err != nil {
			authConn.Close()
			continue
		}

		// 6. 选择模块
		_, err = authConn.Write([]byte(moduleName + "\n"))
		if err != nil {
			authConn.Close()
			continue
		}

		// 7. 等待认证挑战
		n, err = authConn.Read(buffer)
		if err != nil {
			authConn.Close()
			continue
		}

		authResponse := string(buffer[:n])
		if strings.Contains(authResponse, "@RSYNCD: OK") {
			// 模块不需要认证
			if user == "" && pass == "" {
				result := fmt.Sprintf("Rsync服务 %v:%v 模块:%v 无需认证", host, port, moduleName)
				fmt.Println(result)
				return true, nil
			}
		} else if strings.Contains(authResponse, "@RSYNCD: AUTHREQD") {
			if user != "" && pass != "" {
				// 8. 发送认证信息
				authString := fmt.Sprintf("%s %s\n", user, pass)
				_, err = authConn.Write([]byte(authString))
				if err != nil {
					authConn.Close()
					continue
				}

				// 9. 读取认证结果
				n, err = authConn.Read(buffer)
				if err != nil {
					authConn.Close()
					continue
				}

				if !strings.Contains(string(buffer[:n]), "@ERROR") {
					result := fmt.Sprintf("Rsync服务 %v:%v 模块:%v 认证成功 用户名: %v 密码: %v",
						host, port, moduleName, user, pass)
					fmt.Println(result)
					return true, nil
				}
			}
		}
		authConn.Close()
	}

	return false, fmt.Errorf("认证失败或无可用模块")
}
