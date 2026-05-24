package Plugins

import (
	"Qscan/core/pocScan/info"
	"regexp"
	"sync"
)

type CheckDatas struct {
	Body    []byte
	Headers string
}

var (
	infoRegexCache = make(map[string]*regexp.Regexp)
	infoRegexMu    sync.RWMutex
)

func getInfoRegexp(pattern string) *regexp.Regexp {
	infoRegexMu.RLock()
	re, ok := infoRegexCache[pattern]
	infoRegexMu.RUnlock()
	if ok {
		return re
	}
	infoRegexMu.Lock()
	defer infoRegexMu.Unlock()
	re, ok = infoRegexCache[pattern]
	if ok {
		return re
	}
	re = regexp.MustCompile(pattern)
	infoRegexCache[pattern] = re
	return re
}

func InfoCheck(Url string, CheckData *[]CheckDatas) []string {
	var matched bool
	var infoname []string

	for _, data := range *CheckData {
		for _, rule := range info.RuleDatas {
			re := getInfoRegexp(rule.Rule)
			if rule.Type == "code" {
				matched = re.MatchString(string(data.Body))
			} else {
				matched = re.MatchString(data.Headers)
			}
			if matched {
				infoname = append(infoname, rule.Name)
			}
		}
	}

	infoname = removeDuplicateElement(infoname)

	if len(infoname) > 0 {
		return infoname
	}
	return []string{""}
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
