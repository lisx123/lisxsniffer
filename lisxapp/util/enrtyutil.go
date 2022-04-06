package util

import (
	"strconv"
	"strings"
)

//判断是否在FilterRules中
func isInStringArray(s string, ruls []string) bool {
	for _, v := range ruls {
		if strings.EqualFold(v, s) {
			return true
		}

	}
	return false
}
func Textvalitor(s string) error {
	filter := strings.ToLower(s)
	// 将输入的字符串进行切割，以" "空格为分割条件
	strs := strings.SplitN(filter, " ", -1)
	if len(strs) == 0 {
		RightFilter = true
	}
	if len(strs) == 1 {
		if isInStringArray(strs[0], FilterRuls) {
			RightFilter = true
		} else {
			RightFilter = false
		}
	} else {
		if isInStringArray("and", strs) {
			_, err := strconv.ParseInt(strs[len(strs)-1], 0, 0)
			if err != nil {
				RightFilter = false
			}
			RightFilter = true
		}
	}

	return nil

}
