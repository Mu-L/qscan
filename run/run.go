package run

import (
	"Qscan/app"
	"Qscan/core/appfinger"
	"Qscan/core/gonmap"
	"Qscan/core/hydra"
	"Qscan/core/pocScan"
	"Qscan/core/scanner"
	"Qscan/core/slog"
	"Qscan/core/stdio/chinese"
	"Qscan/lib/color"
	"Qscan/lib/misc"
	"Qscan/lib/simplehttp"
	"Qscan/lib/uri"
	"fmt"
	"github.com/atotto/clipboard"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Start() {
	//启用看门狗函数定时输出负载情况
	go watchDog()
	//下发扫描任务
	var wg = &sync.WaitGroup{}
	wg.Add(4)
	IPScanner = generateIPScanner(wg)
	PortScanner = generatePortScanner(wg)
	URLScanner = generateURLScanner(wg)
	HydraScanner = generateHydraScanner(wg)
	//扫描器进入监听状态
	start()
	//开始分发扫描任务
	if app.Setting.ExcludedIp != nil {
		tar := removeRepeat(app.Setting.ExcludedIp, app.Setting.Target)
		fmt.Println(tar)
		for _, expr := range tar {
			pushTarget(expr)
		}
	} else {
		for _, expr := range app.Setting.Target {
			pushTarget(expr)
		}
	}

	slog.Println(slog.INFO, "所有扫描任务已下发完毕")
	//根据扫描情况，关闭scanner
	go stop()
	wg.Wait()
}

func pushTarget(expr string) {
	if expr == "" {
		return
	}
	if expr == "paste" || expr == "clipboard" {
		if clipboard.Unsupported == true {
			slog.Println(slog.ERROR, runtime.GOOS, "clipboard unsupported")
		}
		clipboardStr, _ := clipboard.ReadAll()
		for _, line := range strings.Split(clipboardStr, "\n") {
			line = strings.ReplaceAll(line, "\r", "")
			pushTarget(line)
		}
		return
	}
	if uri.IsIPv4(expr) {
		IPScanner.Push(net.ParseIP(expr))
		if app.Setting.Check == true {
			pushURLTarget(uri.URLParse("http://"+expr), nil)
			pushURLTarget(uri.URLParse("https://"+expr), nil)
		}
		return
	}
	if uri.IsIPv6(expr) {
		slog.Println(slog.WARN, "暂时不支持IPv6的扫描对象：", expr)
		return
	}
	if uri.IsCIDR(expr) {
		for _, ip := range uri.CIDRToIP(expr) {

			pushTarget(ip.String())
		}
		return
	}
	if uri.IsIPRanger(expr) {
		for _, ip := range uri.RangerToIP(expr) {
			pushTarget(ip.String())
		}
		return
	}
	if uri.IsDomain(expr) {
		pushURLTarget(uri.URLParse("http://"+expr), nil)
		pushURLTarget(uri.URLParse("https://"+expr), nil)
		return
	}
	if uri.IsHostPath(expr) {
		pushURLTarget(uri.URLParse("http://"+expr), nil)
		pushURLTarget(uri.URLParse("https://"+expr), nil)
		if app.Setting.Check == false {
			pushTarget(uri.GetNetlocWithHostPath(expr))
		}
		return
	}
	if uri.IsNetlocPort(expr) {
		netloc, port := uri.SplitWithNetlocPort(expr)
		if uri.IsIPv4(netloc) {
			PortScanner.Push(net.ParseIP(netloc), port)
		}
		if uri.IsDomain(netloc) {
			pushURLTarget(uri.URLParse("http://"+expr), nil)
			pushURLTarget(uri.URLParse("https://"+expr), nil)
		}
		if app.Setting.Check == false {
			pushTarget(netloc)
		}
		return
	}
	if uri.IsURL(expr) {
		pushURLTarget(uri.URLParse(expr), nil)
		if app.Setting.Check == false {
			pushTarget(uri.GetNetlocWithURL(expr))
		}
		return
	}
	slog.Println(slog.WARN, "无法识别的Target字符串:", expr)
}

func pushURLTarget(URL *url.URL, response *gonmap.Response) {
	var cli *http.Client
	//判断是否初始化client
	if app.Setting.Proxy != "" || app.Setting.Timeout != 3*time.Second {
		cli = simplehttp.NewClient()
	}
	//判断是否需要设置代理
	if app.Setting.Proxy != "" {
		simplehttp.SetProxy(cli, app.Setting.Proxy)
	}
	//判断是否需要设置超时参数
	if app.Setting.Timeout != 3*time.Second {
		simplehttp.SetTimeout(cli, app.Setting.Timeout)
	}

	//判断是否存在请求修饰性参数
	if len(app.Setting.Host) == 0 && len(app.Setting.Path) == 0 {
		URLScanner.Push(URL, response, nil, cli)
		return
	}

	//如果存在，则逐一建立请求下发队列
	var reqs []*http.Request
	for _, host := range app.Setting.Host {
		req, _ := simplehttp.NewRequest(http.MethodGet, URL.String(), nil)
		req.Host = host
		reqs = append(reqs, req)
	}
	for _, path := range app.Setting.Path {
		req, _ := simplehttp.NewRequest(http.MethodGet, URL.String()+path, nil)
		reqs = append(reqs, req)
	}
	for _, req := range reqs {
		URLScanner.Push(req.URL, response, req, cli)
	}
}

var (
	IPScanner    *scanner.IPClient
	PortScanner  *scanner.PortClient
	URLScanner   *scanner.URLClient
	HydraScanner *scanner.HydraClient
)

func start() {
	go IPScanner.Start()
	go PortScanner.Start()
	go URLScanner.Start()
	go HydraScanner.Start()
	time.Sleep(time.Second * 1)
	//slog.Println(slog.INFO, "Domain、IP、Port、URL、Hydra引擎已准备就绪")
}

func stop() {
	for {
		time.Sleep(time.Second)
		if IPScanner.RunningThreads() == 0 && IPScanner.IsDone() == false {
			IPScanner.Stop()
			slog.Println(slog.DEBUG, "检测到所有IP检测任务已完成，IP扫描引擎已停止")
		}
		if IPScanner.IsDone() == false {
			continue
		}
		if PortScanner.RunningThreads() == 0 && PortScanner.IsDone() == false {
			PortScanner.Stop()
			slog.Println(slog.DEBUG, "检测到所有Port检测任务已完成，Port扫描引擎已停止")
		}
		if PortScanner.IsDone() == false {
			continue
		}
		if URLScanner.RunningThreads() == 0 && URLScanner.IsDone() == false {
			URLScanner.Stop()
			slog.Println(slog.DEBUG, "检测到所有URL检测任务已完成，URL扫描引擎已停止")
		}
		if HydraScanner.RunningThreads() == 0 && HydraScanner.IsDone() == false {
			HydraScanner.Stop()
			slog.Println(slog.DEBUG, "检测到所有暴力破解任务已完成，暴力破解引擎已停止")
		}
	}
}

func generateIPScanner(wg *sync.WaitGroup) *scanner.IPClient {
	IPConfig := scanner.DefaultConfig()
	IPConfig.Threads = 200
	IPConfig.Timeout = 200 * time.Millisecond
	IPConfig.HostDiscoverClosed = app.Setting.ClosePing
	client := scanner.NewIPScanner(IPConfig)
	client.HandlerDie = func(addr net.IP) {
		slog.Println(slog.DEBUG, addr.String(), " is die")
	}
	client.HandlerAlive = func(addr net.IP) {
		//启用端口存活性探测任务下发器
		slog.Println(slog.DEBUG, addr.String(), " is alive")
		for _, port := range app.Setting.Port {
			PortScanner.Push(addr, port)
		}
	}
	client.HandlerError = func(addr net.IP, err error) {
		slog.Println(slog.DEBUG, "IPScanner Error: ", addr.String(), err)
	}
	client.Defer(func() {
		wg.Done()
	})
	return client
}

func getTimeout(i int) time.Duration {
	switch {
	case i > 10000:
		return time.Millisecond * 200
	case i > 5000:
		return time.Millisecond * 300
	case i > 1000:
		return time.Millisecond * 400
	default:
		return time.Millisecond * 500
	}
}

func generatePortScanner(wg *sync.WaitGroup) *scanner.PortClient {
	PortConfig := scanner.DefaultConfig()
	PortConfig.Threads = app.Setting.Threads
	PortConfig.Timeout = getTimeout(len(app.Setting.Port))
	if app.Setting.ScanVersion == true {
		PortConfig.DeepInspection = true
	}
	client := scanner.NewPortScanner(PortConfig)
	client.HandlerClosed = func(addr net.IP, port int) {
		//nothing
	}
	client.HandlerNotMatched = func(addr net.IP, port int, response string) {
		outputUnknownResponse(addr, port, response)
	}
	client.HandlerMatched = func(addr net.IP, port int, response *gonmap.Response) {
		URLRaw := fmt.Sprintf("%s://%s:%d", response.FingerPrint.Service, addr.String(), port)
		if app.Setting.Exploit == true {

			info := app.HostInfo{
				Host:  addr.String(),
				Ports: strconv.Itoa(port),
			}

			if scanFuncs, ok := app.PortScanMap[port]; ok {
				for _, scanFunc := range scanFuncs {
					err := scanFunc(&info)
					if err != nil {

					}
				}
			}
		}
		URL, _ := url.Parse(URLRaw)
		if appfinger.SupportCheck(URL.Scheme) == true {
			pushURLTarget(URL, response)
			return
		}
		outputNmapFinger(URL, response)
		if app.Setting.Hydra == true {
			if protocol := response.FingerPrint.Service; hydra.Ok(protocol) {
				HydraScanner.Push(addr, port, protocol)
			}
		}
	}
	client.HandlerError = func(addr net.IP, port int, err error) {
		slog.Println(slog.DEBUG, "PortScanner Error: ", fmt.Sprintf("%s:%d", addr.String(), port), err)
	}
	client.Defer(func() {
		wg.Done()
	})
	return client
}

func generateURLScanner(wg *sync.WaitGroup) *scanner.URLClient {
	URLConfig := scanner.DefaultConfig()
	URLConfig.Threads = app.Setting.Threads/2 + 1

	client := scanner.NewURLScanner(URLConfig)
	client.HandlerMatched = func(URL *url.URL, banner *appfinger.Banner, finger *appfinger.FingerPrint) {
		outputAppFinger(URL, banner, finger)
		if app.Setting.Exploit == true {
			url := URL.Scheme + "://" + URL.Host
			info := app.HostInfo{
				Host:  URL.Scheme,
				Ports: URL.Hostname(),
				Url:   url,
			}
			pocScan.WebTitle(&info)
		}
	}
	client.HandlerError = func(url *url.URL, err error) {
		slog.Println(slog.DEBUG, "URLScanner Error: ", url.String(), err)
	}
	client.Defer(func() {
		wg.Done()
	})
	return client
}

func generateHydraScanner(wg *sync.WaitGroup) *scanner.HydraClient {
	HydraConfig := scanner.DefaultConfig()
	HydraConfig.Threads = 10

	client := scanner.NewHydraScanner(HydraConfig)
	client.HandlerSuccess = func(addr net.IP, port int, protocol string, auth *hydra.Auth) {
		outputHydraSuccess(addr, port, protocol, auth)
	}
	client.HandlerError = func(addr net.IP, port int, protocol string, err error) {
		slog.Println(slog.DEBUG, fmt.Sprintf("%s://%s:%d", protocol, addr.String(), port), err)
	}
	client.Defer(func() {
		wg.Done()
	})
	return client
}

func outputHydraSuccess(addr net.IP, port int, protocol string, auth *hydra.Auth) {
	var target = fmt.Sprintf("%s://%s:%d", protocol, addr.String(), port)
	var m = auth.Map()
	URL, _ := url.Parse(target)
	OutputHandler(URL, color.Important("CrackSuccess"), m)
}

func outputNmapFinger(URL *url.URL, resp *gonmap.Response) {
	finger := resp.FingerPrint
	m := misc.ToMap(finger)

	m["Response"] = resp.Raw
	m["IP"] = URL.Hostname()
	m["Port"] = URL.Port()
	OutputHandler(URL, finger.Service, m)
}

func outputAppFinger(URL *url.URL, banner *appfinger.Banner, finger *appfinger.FingerPrint) {
	m := misc.ToMap(finger)
	m["Service"] = URL.Scheme
	m["FoundDomain"] = banner.FoundDomain
	m["FoundIP"] = banner.FoundIP
	m["Response"] = banner.Response
	m["Cert"] = banner.Cert
	m["Header"] = banner.Header
	m["Body"] = banner.Body
	m["ICP"] = banner.ICP
	m["FingerPrint"] = m["ProductName"]
	delete(m, "ProductName")
	//增加IP、Domain、Port字段
	m["Port"] = uri.GetURLPort(URL)
	if m["Port"] == "" {
		slog.Println(slog.WARN, "无法获取端口号：", URL)
	}
	if hostname := URL.Hostname(); uri.IsIPv4(hostname) {
		m["IP"] = hostname
	}
	OutputHandler(URL, banner.Title, m)
}

func outputUnknownResponse(addr net.IP, port int, response string) {
	//输出结果
	target := fmt.Sprintf("unknown://%s:%d", addr.String(), port)
	URL, _ := url.Parse(target)
	OutputHandler(URL, "无法识别该协议", map[string]string{
		"Response": response,
		"IP":       URL.Hostname(),
		"Port":     strconv.Itoa(port),
	})
}

//输出结果，排除响应为空的结果
/*func outputOpenResponse(addr net.IP, port int) {
	protocol := gonmap.GuessProtocol(port)
	target := fmt.Sprintf("%s://%s:%d", protocol, addr.String(), port)
	URL, _ := url.Parse(target)
	outputHandler(URL, "response is empty", map[string]string{
		"IP":   URL.Hostname(),
		"Port": strconv.Itoa(port),
	})
}*/

var (
	disableKey       = []string{"MatchRegexString", "Service", "ProbeName", "Response", "Cert", "Header", "Body", "IP"}
	ImportantKey     = []string{"ProductName", "DeviceType"}
	VaryImportantKey = []string{"Hostname", "FingerPrint", "ICP"}
)

func getHTTPDigest(s string) string {
	var length = 24
	var digestBuf []rune
	_, body := simplehttp.SplitHeaderAndBody(s)
	body = chinese.ToUTF8(body)
	for _, r := range []rune(body) {
		buf := []byte(string(r))
		if len(digestBuf) == length {
			return string(digestBuf)
		}
		if len(buf) > 1 {
			digestBuf = append(digestBuf, r)
		}
	}
	return string(digestBuf) + misc.StrRandomCut(body, length-len(digestBuf))
}

func getRawDigest(s string) string {
	var length = 24
	if len(s) < length {
		return s
	}
	var digestBuf []rune
	for _, r := range []rune(s) {
		if len(digestBuf) == length {
			return string(digestBuf)
		}
		if 0x20 <= r && r <= 0x7E {
			digestBuf = append(digestBuf, r)
		}
	}
	return string(digestBuf) + misc.StrRandomCut(s, length-len(digestBuf))
}

func OutputHandler(URL *url.URL, keyword string, m map[string]string) {
	m = misc.FixMap(m)
	if respRaw := m["Response"]; respRaw != "" {
		if m["Service"] == "http" || m["Service"] == "https" {
			m["Digest"] = strconv.Quote(getHTTPDigest(respRaw))
		} else {
			m["Digest"] = strconv.Quote(getRawDigest(respRaw))
		}
	}
	m["Length"] = strconv.Itoa(len(m["Response"]))
	sourceMap := misc.CloneMap(m)
	for _, keyword := range disableKey {
		delete(m, keyword)
	}
	for key, value := range m {
		if key == "FingerPrint" {
			continue
		}
		m[key] = misc.StrRandomCut(value, 24)
	}
	fingerPrint := color.StrMapRandomColor(m, true, ImportantKey, VaryImportantKey)
	fingerPrint = misc.FixLine(fingerPrint)
	format := "%-30v %-" + strconv.Itoa(misc.AutoWidth(color.Clear(keyword), 26+color.Count(keyword))) + "v %s"
	printStr := fmt.Sprintf(format, URL.String(), keyword, fingerPrint)
	slog.Println(slog.DATA, printStr)

	if jw := app.Setting.OutputJson; jw != nil {
		sourceMap["URL"] = URL.String()
		sourceMap["Keyword"] = keyword
		jw.Push(sourceMap)
	}
	if cw := app.Setting.OutputCSV; cw != nil {
		sourceMap["URL"] = URL.String()
		sourceMap["Keyword"] = keyword
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

func watchDog() {
	for {
		time.Sleep(time.Second * 1)
		var (
			nIP    = IPScanner.RunningThreads()
			nPort  = PortScanner.RunningThreads()
			nURL   = URLScanner.RunningThreads()
			nHydra = HydraScanner.RunningThreads()
		)
		if time.Now().Unix()%180 == 0 {
			warn := fmt.Sprintf("当前存活协程数：IP：%d 个，Port：%d 个，URL：%d 个，Hydra：%d 个", nIP, nPort, nURL, nHydra)
			slog.Println(slog.WARN, warn)
		}
	}
}

// var1 是要去除的
// var2 是最后要保留的
func removeRepeat(var1, var2 []string) []string {
	set := make(map[string]bool)
	for _, v := range var1 {
		set[v] = true
	}

	result := []string{}
	for _, v := range var2 {
		if !set[v] {
			result = append(result, v)
		}
	}

	return result
}
