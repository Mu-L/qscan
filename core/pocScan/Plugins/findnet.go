package Plugins

import (
	"Qscan/app"
	"Qscan/core/pocScan/lib"
	"Qscan/core/slog"
	"Qscan/lib/misc"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/lcvvvv/stdio/chinese"
	"strconv"
	"strings"
	"time"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func Findnet(info *app.HostInfo) error {
	err := FindnetScan(info)
	return err
}

func FindnetScan(info *app.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, 135)
	conn, err := lib.WrapperTcpWithTimeout("tcp", realhost, time.Duration(3)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(3) * time.Second))
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV1)
	if err != nil {
		return err
	}
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV2)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return err
	}
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return err
	}
	err = read(text, info.Host)
	return err
}

func HexUnicodeStringToString(src string) string {
	sText := ""
	if len(src)%4 != 0 {
		src += src[:len(src)-len(src)%4]
	}
	for i := 0; i < len(src); i = i + 4 {
		sText += "\\u" + src[i+2:i+4] + src[i:i+2]
	}

	textUnquoted := sText
	sUnicodev := strings.Split(textUnquoted, "\\u")
	var context string
	for _, v := range sUnicodev {
		if len(v) < 1 {
			continue
		}
		temp, err := strconv.ParseInt(v, 16, 32)
		if err != nil {
			return ""
		}
		context += fmt.Sprintf("%c", temp)
	}
	return context
}

func read(text []byte, host string) error {
	var printStr string

	encodedStr := hex.EncodeToString(text)

	hn := ""
	for i := 0; i < len(encodedStr)-4; i = i + 4 {
		if encodedStr[i:i+4] == "0000" {
			break
		}
		hn += encodedStr[i : i+4]
	}

	var IPP string
	var userName string
	var name string
	name = HexUnicodeStringToString(hn)

	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostnames, "000000")
	result := "NetInfo://" + host + ":135"
	if name != "" {
		userName += "," + name
	}
	hostname = hostname[1:]
	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		host, err := hex.DecodeString(hostname[i])
		if err != nil {
			return err
		}
		hostQ := strings.TrimLeft(string(host), " ")
		hostQ = strings.TrimRight(hostQ, " ")
		IPP += "," + hostQ
	}
	printStr = fmt.Sprintf("%-30v \n    %v \n    %s", result, "主机名："+strings.ReplaceAll(userName, ",", "\n       └─ "), "发现的网络接口："+strings.ReplaceAll(IPP, ",", "\n       └─ "))

	// 保存
	m := make(map[string]string)
	sourceMap := misc.CloneMap(m)
	if jw := app.Setting.OutputJson; jw != nil {
		sourceMap["URL"] = result
		sourceMap["Keyword"] = "NetInfo"
		sourceMap["主机名"] = userName
		sourceMap["网络接口"] = IPP
		jw.Push(sourceMap)
	}
	if cw := app.Setting.OutputCSV; cw != nil {
		sourceMap["URL"] = result
		sourceMap["Keyword"] = "NetInfo"
		sourceMap["主机名"] = userName
		sourceMap["网络接口"] = IPP
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

	slog.Println(slog.DATA, printStr)
	return nil
}
