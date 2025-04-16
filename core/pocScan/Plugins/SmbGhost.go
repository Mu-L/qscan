package Plugins

import (
	"Qscan/app"
	"Qscan/core/pocScan/lib"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"bytes"
	"fmt"
	"strconv"
	"time"
)

const (
	pkt = "\x00" + // session
		"\x00\x00\xc0" + // legth

		"\xfeSMB@\x00" + // protocol

		//[MS-SMB2]: SMB2 NEGOTIATE Request
		//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5

		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x1f\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +

		// [MS-SMB2]: SMB2 NEGOTIATE_CONTEXT
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7

		"$\x00" +
		"\x08\x00" +
		"\x01\x00" +
		"\x00\x00" +
		"\x7f\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"x\x00" +
		"\x00\x00" +
		"\x02\x00" +
		"\x00\x00" +
		"\x02\x02" +
		"\x10\x02" +
		"\x22\x02" +
		"$\x02" +
		"\x00\x03" +
		"\x02\x03" +
		"\x10\x03" +
		"\x11\x03" +
		"\x00\x00\x00\x00" +

		// [MS-SMB2]: SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5

		"\x01\x00" +
		"&\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" +
		"\x20\x00" +
		"\x01\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00" +

		// [MS-SMB2]: SMB2_COMPRESSION_CAPABILITIES
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271

		"\x03\x00" +
		"\x0e\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" + //CompressionAlgorithmCount
		"\x00\x00" +
		"\x01\x00\x00\x00" +
		"\x01\x00" + //LZNT1
		"\x00\x00" +
		"\x00\x00\x00\x00"
)

// SmbGhost 检测SMB Ghost漏洞(CVE-2020-0796)的入口函数
func SmbGhost(info *app.HostInfo) error {
	// 执行实际的SMB Ghost漏洞扫描
	err := SmbGhostScan(info)
	return err
}

// SmbGhostScan 执行具体的SMB Ghost漏洞检测逻辑
func SmbGhostScan(info *app.HostInfo) error {
	// 设置扫描参数
	ip := info.Host
	port := 445 // SMB服务默认端口
	timeout := time.Duration(3) * time.Second

	// 构造目标地址
	addr := fmt.Sprintf("%s:%v", ip, port)

	// 建立TCP连接
	conn, err := lib.WrapperTcpWithTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close() // 确保连接最终被关闭

	// 发送SMB协议探测数据包
	if _, err = conn.Write([]byte(pkt)); err != nil {
		return err
	}

	// 准备接收响应
	buff := make([]byte, 1024)

	// 设置读取超时
	if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// 读取响应数据
	n, err := conn.Read(buff)
	if err != nil || n == 0 {
		return err
	}

	// 分析响应数据，检测是否存在漏洞
	// 检查条件：
	// 1. 响应包含"Public"字符串
	// 2. 响应长度大于等于76字节
	// 3. 特征字节匹配 (0x11,0x03) 和 (0x02,0x00)
	if bytes.Contains(buff[:n], []byte("Public")) &&
		len(buff[:n]) >= 76 &&
		bytes.Equal(buff[72:74], []byte{0x11, 0x03}) &&
		bytes.Equal(buff[74:76], []byte{0x02, 0x00}) {

		// 发现漏洞，记录结果
		result := fmt.Sprintf("%v CVE-2020-0796 SmbGhost Vulnerable", ip)
		fmt.Println(result)
		m := make(map[string]string)
		sourceMap := misc.CloneMap(m)
		if jw := app.Setting.OutputJson; jw != nil {
			sourceMap["URL"] = info.Host
			sourceMap["Keyword"] = "CrackSuccess"
			sourceMap["Status"] = "smbGhost"
			sourceMap["port"] = info.Ports
			sourceMap["type"] = "CVE-2020-0796"
			jw.Push(sourceMap)
		}
		if cw := app.Setting.OutputCSV; cw != nil {
			sourceMap["URL"] = info.Host
			sourceMap["Keyword"] = "CrackSuccess"
			sourceMap["Status"] = "smbGhost"
			sourceMap["port"] = info.Ports
			sourceMap["type"] = "CVE-2020-0796"
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
