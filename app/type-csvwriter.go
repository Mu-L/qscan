package app

import (
	"encoding/csv"
	"sync"
)

type CSVWriter struct {
	f     *csv.Writer
	title []string
	mutex *sync.Mutex
}

func (cw *CSVWriter) inTitle(title string) bool {
	for _, value := range cw.title {
		if value == title {
			return true
		}
	}
	return false
}

func (cw *CSVWriter) Push(m map[string]string) {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()
	var cells []string
	// clone map to avoid mutating caller's map
	mCopy := make(map[string]string, len(m))
	for k, v := range m {
		mCopy[k] = v
	}
	for _, key := range cw.title {
		if value, ok := mCopy[key]; ok {
			cells = append(cells, value)
			delete(mCopy, key)
		} else {
			cells = append(cells, "")
		}
	}
	for key, value := range mCopy {
		cells = append(cells, value)
		cw.title = append(cw.title, key)
	}
	cw.f.Write(cells)
	cw.f.Flush()
}
