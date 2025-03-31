package Plugins

import (
	"Qscan/core/pocScan/info"
	"regexp"
)

type CheckDatas struct {
	Body    []byte
	Headers string
}

func InfoCheck(Url string, CheckData *[]CheckDatas) []string {
	var matched bool
	var infoname []string

	for _, data := range *CheckData {
		for _, rule := range info.RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoname = append(infoname, rule.Name)
			}
		}
		//flag, name := CalcMd5(data.Body)

		//if flag == true {
		//	infoname = append(infoname, name)
		//}
	}

	infoname = removeDuplicateElement(infoname)

	if len(infoname) > 0 {
		//fmt.Sprintf("[+] InfoScan %-25v %s ", Url, infoname)
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
