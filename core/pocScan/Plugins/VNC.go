package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"github.com/mitchellh/go-vnc"
	"net"
	"strconv"
	"time"
)

func VncScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	modename := "vnc"
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试密码组合 (总密码数: %d)", totalPass)

	tried := 0

	// 遍历所有密码
	for _, pass := range app.Passwords {
		tried++
		fmt.Printf("[%d/%d] 尝试密码: %s", tried, totalPass, pass)

		// 重试循环
		for retryCount := 0; retryCount < maxRetries; retryCount++ {
			if retryCount > 0 {
				fmt.Printf("第%d次重试密码: %s", retryCount+1, pass)
			}

			done := make(chan struct {
				success bool
				err     error
			}, 1)

			go func(pass string) {
				success, err := VncConn(info, pass)
				select {
				case done <- struct {
					success bool
					err     error
				}{success, err}:
				default:
				}
			}(pass)

			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					// 连接成功
					successLog := fmt.Sprintf("%s://%s 密码: %v", modename, target, pass)
					fmt.Println(successLog)

					// 保存结果
					m := make(map[string]string)
					sourceMap := misc.CloneMap(m)
					if jw := app.Setting.OutputJson; jw != nil {
						sourceMap["URL"] = info.Host
						sourceMap["Keyword"] = "CrackSuccess"
						sourceMap["Status"] = "vulnerable"
						sourceMap["port"] = info.Ports
						sourceMap["service"] = "vnc"
						sourceMap["password"] = pass
						sourceMap["type"] = "weak-password"
						jw.Push(sourceMap)
					}
					if cw := app.Setting.OutputCSV; cw != nil {
						sourceMap["URL"] = info.Host
						sourceMap["Keyword"] = "CrackSuccess"
						sourceMap["Status"] = "vulnerable"
						sourceMap["port"] = info.Ports
						sourceMap["service"] = "vnc"
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
				errlog := fmt.Sprintf("%s://%s 尝试密码: %v 错误: %v",
					modename, target, pass, err)
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

	fmt.Printf("扫描完成，共尝试 %d 个密码", tried)
	return tmperr
}

// VncConn 尝试建立VNC连接
func VncConn(info *app.HostInfo, pass string) (flag bool, err error) {
	flag = false
	Host, Port := info.Host, info.Ports

	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", Host, Port),
		time.Duration(3)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 配置VNC客户端
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: pass,
			},
		},
	}

	// 尝试VNC认证
	client, err := vnc.Client(conn, config)
	if err == nil {
		defer client.Close()
		flag = true
	}

	return
}
