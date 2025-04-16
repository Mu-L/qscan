package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"github.com/IBM/sarama"
	"strconv"
	"strings"
	"time"
)

func KafkaScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	fmt.Printf("开始扫描 %s", target)

	// 尝试无认证访问
	fmt.Println("尝试无认证访问...")
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			fmt.Printf("第%d次重试无认证访问", retryCount+1)
		}
		flag, err := KafkaConn(info, "", "")
		if flag && err == nil {
			// 保存无认证访问结果
			m := make(map[string]string)
			sourceMap := misc.CloneMap(m)
			if jw := app.Setting.OutputJson; jw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "vulnerable"
				sourceMap["port"] = info.Ports
				sourceMap["service"] = "kafka"
				sourceMap["info"] = "无认证访问"
				sourceMap["type"] = "unauthorized-access"
				jw.Push(sourceMap)
			}
			if cw := app.Setting.OutputCSV; cw != nil {
				sourceMap["URL"] = info.Host
				sourceMap["Keyword"] = "CrackSuccess"
				sourceMap["Status"] = "vulnerable"
				sourceMap["port"] = info.Ports
				sourceMap["service"] = "kafka"
				sourceMap["info"] = "无认证访问"
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
			fmt.Printf("Kafka服务 %s 无需认证即可访问", target)
			return nil
		}
		if err != nil && app.CheckErrs(err) != nil {
			if retryCount < maxRetries-1 {
				continue
			}
			return err
		}
		break
	}

	totalUsers := len(app.Userdict["kafka"])
	totalPass := len(app.Passwords)
	fmt.Printf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass)

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range app.Userdict["kafka"] {
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
					success, err := KafkaConn(info, user, pass)
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
						// 保存爆破成功结果
						m := make(map[string]string)
						sourceMap := misc.CloneMap(m)
						if jw := app.Setting.OutputJson; jw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "vulnerable"
							sourceMap["port"] = info.Ports
							sourceMap["service"] = "kafka"
							sourceMap["username"] = user
							sourceMap["password"] = pass
							sourceMap["type"] = "unauthorized-access"
							jw.Push(sourceMap)
						}
						if cw := app.Setting.OutputCSV; cw != nil {
							sourceMap["URL"] = info.Host
							sourceMap["Keyword"] = "CrackSuccess"
							sourceMap["Status"] = "vulnerable"
							sourceMap["port"] = info.Ports
							sourceMap["service"] = "kafka"
							sourceMap["username"] = user
							sourceMap["password"] = pass
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
						fmt.Printf("Kafka服务 %s 爆破成功 用户名: %s 密码: %s", target, user, pass)
						return nil
					}
				case <-time.After(time.Duration(3) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					fmt.Printf("Kafka服务 %s 尝试失败 用户名: %s 密码: %s 错误: %v",
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

// KafkaConn 尝试 Kafka 连接
func KafkaConn(info *app.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second

	config := sarama.NewConfig()
	config.Net.DialTimeout = timeout
	config.Net.TLS.Enable = false
	config.Version = sarama.V2_0_0_0

	// 设置 SASL 配置
	if user != "" || pass != "" {
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		config.Net.SASL.User = user
		config.Net.SASL.Password = pass
		config.Net.SASL.Handshake = true
	}

	brokers := []string{fmt.Sprintf("%s:%s", host, port)}

	// 尝试作为消费者连接测试
	consumer, err := sarama.NewConsumer(brokers, config)
	if err == nil {
		defer consumer.Close()
		return true, nil
	}

	// 如果消费者连接失败，尝试作为客户端连接
	client, err := sarama.NewClient(brokers, config)
	if err == nil {
		defer client.Close()
		return true, nil
	}

	// 检查错误类型
	if strings.Contains(err.Error(), "SASL") ||
		strings.Contains(err.Error(), "authentication") ||
		strings.Contains(err.Error(), "credentials") {
		return false, fmt.Errorf("认证失败")
	}

	return false, err
}
