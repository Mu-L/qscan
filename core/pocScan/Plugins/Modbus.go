package Plugins

import (
	"Qscan/app"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/misc"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ModbusScan 执行 Modbus 服务扫描
func ModbusScan(info *app.HostInfo) error {
	host, port := info.Host, info.Ports
	timeout := time.Duration(3) * time.Second

	// 尝试建立连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 构造Modbus TCP请求包 - 读取设备ID
	request := buildModbusRequest()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(timeout))

	// 发送请求
	_, err = conn.Write(request)
	if err != nil {
		return fmt.Errorf("发送Modbus请求失败: %v", err)
	}

	// 读取响应
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("读取Modbus响应失败: %v", err)
	}

	// 验证响应
	if isValidModbusResponse(response[:n]) {
		// 获取设备信息
		deviceInfo := parseModbusResponse(response[:n])

		// 保存扫描结果
		m := make(map[string]string)
		sourceMap := misc.CloneMap(m)
		if jw := app.Setting.OutputJson; jw != nil {
			sourceMap["URL"] = info.Host
			sourceMap["Keyword"] = "CrackSuccess"
			sourceMap["Status"] = "modbus"
			sourceMap["port"] = info.Ports
			sourceMap["device_id"] = deviceInfo
			sourceMap["type"] = "unauthorized-access"
			jw.Push(sourceMap)
		}
		if cw := app.Setting.OutputCSV; cw != nil {
			sourceMap["URL"] = info.Host
			sourceMap["Keyword"] = "CrackSuccess"
			sourceMap["Status"] = "modbus"
			sourceMap["port"] = info.Ports
			sourceMap["device_id"] = deviceInfo
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

		// 控制台输出
		fmt.Printf("Modbus服务 %v:%v 无认证访问", host, port)
		if deviceInfo != "" {
			fmt.Printf("设备信息: %s", deviceInfo)
		}

		return nil
	}

	return fmt.Errorf("非Modbus服务或访问被拒绝")
}

// buildModbusRequest 构建Modbus TCP请求包
func buildModbusRequest() []byte {
	request := make([]byte, 12)

	// Modbus TCP头部
	binary.BigEndian.PutUint16(request[0:], 0x0001) // 事务标识符
	binary.BigEndian.PutUint16(request[2:], 0x0000) // 协议标识符
	binary.BigEndian.PutUint16(request[4:], 0x0006) // 长度
	request[6] = 0x01                               // 单元标识符

	// Modbus 请求
	request[7] = 0x01                                // 功能码: Read Coils
	binary.BigEndian.PutUint16(request[8:], 0x0000)  // 起始地址
	binary.BigEndian.PutUint16(request[10:], 0x0001) // 读取数量

	return request
}

// isValidModbusResponse 验证Modbus响应是否有效
func isValidModbusResponse(response []byte) bool {
	if len(response) < 9 {
		return false
	}

	// 检查协议标识符
	protocolID := binary.BigEndian.Uint16(response[2:])
	if protocolID != 0 {
		return false
	}

	// 检查功能码
	funcCode := response[7]
	if funcCode == 0x81 { // 错误响应
		return false
	}

	return true
}

// parseModbusResponse 解析Modbus响应获取设备信息
func parseModbusResponse(response []byte) string {
	if len(response) < 9 {
		return ""
	}

	unitID := response[6]
	return fmt.Sprintf("Unit ID: %d", unitID)
}
