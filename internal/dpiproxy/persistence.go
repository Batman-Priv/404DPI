package dpiproxy

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

func (s *ProxyServer) loadStrategyCache() {
	if s.config.StrategyCacheFile == "" {
		return
	}
	data, err := os.ReadFile(s.config.StrategyCacheFile)
	if err != nil {
		return
	}
	var m map[string]strategyRecordJSON
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("[WARN] could not parse strategy cache %s: %v", s.config.StrategyCacheFile, err)
		return
	}
	for k, v := range m {
		s.stratCache.Store(k, recordFromJSON(v))
	}
	if len(m) > 0 {
		log.Printf("[INFO] loaded %d cached fragmentation strategy(ies) from %s", len(m), s.config.StrategyCacheFile)
	}
}

func (s *ProxyServer) saveStrategyCache() {
	if s.config.StrategyCacheFile == "" {
		return
	}
	m := map[string]strategyRecordJSON{}
	s.stratCache.Range(func(k, v interface{}) bool {
		m[k.(string)] = v.(*StrategyRecord).snapshot()
		return true
	})
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	if err := writeFileAtomic(s.config.StrategyCacheFile, data, 0600); err != nil && s.errorLog != nil {
		s.errorLog.Printf("could not save strategy cache to %s: %v", s.config.StrategyCacheFile, err)
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func (s *ProxyServer) periodicStrategySave() {
	if s.config.StrategyCacheFile == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.saveStrategyCache()
		}
	}
}
