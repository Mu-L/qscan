package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SmtpScan 执行 SMTP 服务扫描
func SmtpScanQ(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)
	fmt.Println("尝试匿名访问...")

	// 先测试匿名访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := SmtpConn(info, "", "")
		if flag && err == nil {
			msg := fmt.Sprintf("SMTP服务 %s 允许匿名访问", target)
			fmt.Println(msg)

			// 保存匿名访问结果
			m := make(map[string]string)
			sourceMap := misc.CloneMap(m)
			if jw := app.Setting.OutputJson; jw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "smtp"
				sourceMap["port"] = info.Ports
				sourceMap["type"] = "anonymous-access"
				jw.Push(sourceMap)
			}
			if cw := app.Setting.OutputCSV; cw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "smtp"
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
			errlog := fmt.Sprintf("smtp %s anonymous %v", target, err)
			fmt.Println(errlog)

			if retryErr := app.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	totalUsers := len(app.Userdict["smtp"])
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)\n", totalUsers, totalPass)

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range app.Userdict["smtp"] {
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
					flag, err := SmtpConn(info, user, pass)
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
						msg := fmt.Sprintf("SMTP服务 %s 爆破成功 用户名: %v 密码: %v", target, user, pass)
						fmt.Println(msg)

						// 保存成功爆破结果
						m := make(map[string]string)
						sourceMap := misc.CloneMap(m)
						if jw := app.Setting.OutputJson; jw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "rabbitmq"
							sourceMap["port"] = info.Ports
							sourceMap["username"] = user
							sourceMap["password"] = pass
							sourceMap["type"] = "weak-password"
							jw.Push(sourceMap)
						}
						if cw := app.Setting.OutputCSV; cw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "rabbitmq"
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
						}
						return nil
					}
				case <-time.After(time.Duration(3) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("SMTP服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v",
						target, user, pass, err)
					fmt.Println(errlog)

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

// SmtpConn 尝试 SMTP 连接
func SmtpConn(info *app.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		err = client.Auth(auth)
		if err != nil {
			return false, err
		}
	}

	err = client.Mail("test@test.com")
	if err != nil {
		return false, err
	}

	return true, nil
}
