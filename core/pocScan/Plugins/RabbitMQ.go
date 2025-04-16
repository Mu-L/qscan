package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"net"
	"strconv"
	"strings"
	"time"
)

// RabbitMQScan 执行 RabbitMQ 服务扫描
func RabbitMQScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)
	fmt.Println("尝试默认账号 guest/guest")

	// 先测试默认账号 guest/guest
	user, pass := "guest", "guest"
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			fmt.Printf("第%d次重试默认账号: guest/guest", retryCount+1)
		}

		done := make(chan struct {
			success bool
			err     error
		}, 1)

		go func() {
			success, err := RabbitMQConn(info, user, pass)
			select {
			case done <- struct {
				success bool
				err     error
			}{success, err}:
			default:
			}
		}()

		var err error
		select {
		case result := <-done:
			err = result.err
			if result.success && err == nil {
				successMsg := fmt.Sprintf("RabbitMQ服务 %s 连接成功 用户名: %v 密码: %v", target, user, pass)
				fmt.Println(successMsg)

				// 保存结果
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
			errlog := fmt.Sprintf("RabbitMQ服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v",
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

	totalUsers := len(app.Userdict["rabbitmq"])
	totalPass := len(app.Passwords)
	total := totalUsers * totalPass
	tried := 0

	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass)

	// 遍历其他用户名密码组合
	for _, user := range app.Userdict["rabbitmq"] {
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
					success, err := RabbitMQConn(info, user, pass)
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
						successMsg := fmt.Sprintf("RabbitMQ服务 %s 连接成功 用户名: %v 密码: %v",
							target, user, pass)
						fmt.Println(successMsg)

						// 保存结果
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
					errlog := fmt.Sprintf("RabbitMQ服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v",
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

	fmt.Printf("扫描完成，共尝试 %d 个组合", tried+1)
	return tmperr
}

// RabbitMQConn 尝试 RabbitMQ 连接
func RabbitMQConn(info *app.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second

	// 构造 AMQP URL
	amqpURL := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	// 配置连接
	config := amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		},
	}

	// 尝试连接
	conn, err := amqp.DialConfig(amqpURL, config)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 如果成功连接
	if conn != nil {
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
