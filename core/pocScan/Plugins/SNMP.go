package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"strconv"
	"strings"
	"time"
)

// SNMPScan 执行SNMP服务扫描
func SNMPScan(info *app.HostInfo) (tmperr error) {

	maxRetries := 3
	portNum, _ := strconv.Atoi(info.Ports)
	defaultCommunities := []string{"public", "private", "cisco", "community"}
	timeout := time.Duration(3) * time.Second
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	fmt.Printf("开始扫描 %s", target)
	fmt.Printf("尝试默认 community 列表 (总数: %d)", len(defaultCommunities))

	tried := 0
	total := len(defaultCommunities)

	for _, community := range defaultCommunities {
		tried++
		fmt.Printf("[%d/%d] 尝试 community: %s", tried, total, community)

		for retryCount := 0; retryCount < maxRetries; retryCount++ {
			if retryCount > 0 {
				fmt.Printf("第%d次重试: community: %s", retryCount+1, community)
			}

			done := make(chan struct {
				success bool
				sysDesc string
				err     error
			}, 1)

			go func(community string) {
				success, sysDesc, err := SNMPConnect(info, community, portNum)
				select {
				case done <- struct {
					success bool
					sysDesc string
					err     error
				}{success, sysDesc, err}:
				default:
				}
			}(community)

			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					successMsg := fmt.Sprintf("SNMP服务 %s community: %v 连接成功", target, community)
					if result.sysDesc != "" {
						successMsg += fmt.Sprintf(" System: %v", result.sysDesc)
					}
					fmt.Println(successMsg)

					// 保存结果
					m := make(map[string]string)
					sourceMap := misc.CloneMap(m)
					if jw := app.Setting.OutputJson; jw != nil {
						sourceMap["URL"] = info.Host
						sourceMap["Keyword"] = "CrackSuccess"
						sourceMap["Status"] = "snmp"
						sourceMap["port"] = info.Ports
						sourceMap["community"] = community
						sourceMap["system"] = result.sysDesc
						sourceMap["type"] = "weak-password"
						jw.Push(sourceMap)
					}
					if cw := app.Setting.OutputCSV; cw != nil {
						sourceMap["URL"] = info.Host
						sourceMap["Keyword"] = "CrackSuccess"
						sourceMap["Status"] = "snmp"
						sourceMap["port"] = info.Ports
						sourceMap["community"] = community
						sourceMap["system"] = result.sysDesc
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
			case <-time.After(timeout):
				err = fmt.Errorf("连接超时")
			}

			if err != nil {
				errlog := fmt.Sprintf("SNMP服务 %s 尝试失败 community: %v 错误: %v",
					target, community, err)
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

	fmt.Printf("扫描完成，共尝试 %d 个 community", tried)
	return tmperr
}

// SNMPConnect 尝试SNMP连接
func SNMPConnect(info *app.HostInfo, community string, portNum int) (bool, string, error) {
	host := info.Host
	timeout := time.Duration(3) * time.Second

	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(portNum),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		return false, "", err
	}
	defer snmp.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := snmp.Get(oids)
	if err != nil {
		return false, "", err
	}

	if len(result.Variables) > 0 {
		var sysDesc string
		if result.Variables[0].Type != gosnmp.NoSuchObject {
			sysDesc = strings.TrimSpace(string(result.Variables[0].Value.([]byte)))
		}
		return true, sysDesc, nil
	}

	return false, "", fmt.Errorf("认证失败")
}
