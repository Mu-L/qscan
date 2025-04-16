package Plugins

import (
	"Qscan/app"
	"Qscan/core/pocScan/lib"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MemcachedScan 检测Memcached未授权访问
func MemcachedScan(info *app.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	timeout := time.Duration(3) * time.Second

	// 建立TCP连接
	client, err := lib.WrapperTcpWithTimeout("tcp", realhost, timeout)
	if err != nil {
		return err
	}
	defer client.Close()

	// 设置超时时间
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// 发送stats命令
	if _, err := client.Write([]byte("stats\n")); err != nil {
		return err
	}

	// 读取响应
	rev := make([]byte, 1024)
	n, err := client.Read(rev)
	if err != nil {
		fmt.Printf("Memcached %v:%v %v", info.Host, info.Ports, err)
		return err
	}

	// 检查响应内容
	if strings.Contains(string(rev[:n]), "STAT") {
		// 保存结果
		m := make(map[string]string)
		sourceMap := misc.CloneMap(m)
		if jw := app.Setting.OutputJson; jw != nil {
			sourceMap["URL"] = info.Host
			sourceMap["Keyword"] = "CrackSuccess"
			sourceMap["Status"] = "vulnerable"
			sourceMap["port"] = info.Ports
			sourceMap["service"] = "memcached"
			sourceMap["description"] = "Memcached unauthorized access"
			sourceMap["type"] = "unauthorized-access"
			jw.Push(sourceMap)
		}
		if cw := app.Setting.OutputCSV; cw != nil {
			sourceMap["URL"] = info.Host
			sourceMap["Keyword"] = "CrackSuccess"
			sourceMap["Status"] = "vulnerable"
			sourceMap["port"] = info.Ports
			sourceMap["service"] = "memcached"
			sourceMap["description"] = "Memcached unauthorized access"
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
		fmt.Printf("Memcached %s 未授权访问", realhost)
	}

	return nil
}
