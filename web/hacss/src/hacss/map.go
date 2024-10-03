package hacss

import (
	"go.dedis.ch/kyber/v3"
	"sync"
)

type IntPolyresultMap struct {
	m map[int]PolyResult
	sync.RWMutex
}

func (s *IntPolyresultMap) Init() {
	s.Lock()
	defer s.Unlock()
	s.m = make(map[int]PolyResult)
}

func (s *IntPolyresultMap) Delete(key int) {
	s.Lock()
	defer s.Unlock()
	_, exist := s.m[key]
	if exist {
		delete(s.m, key)
	}
}

func (s *IntPolyresultMap) Get(key int) (PolyResult, bool) {
	s.Lock()
	defer s.Unlock()
	_, exist := s.m[key]
	if exist {
		return s.m[key], true
	}
	var emp PolyResult
	return emp, false
}

func (s *IntPolyresultMap) GetAll() map[int]PolyResult {
	s.Lock()
	defer s.Unlock()
	return s.m
}

func (s *IntPolyresultMap) Insert(key int, value PolyResult) {
	s.Lock()
	defer s.Unlock()
	s.m[key] = value
}

func (s *IntPolyresultMap) GetCount() int {
	s.Lock()
	defer s.Unlock()
	var tmp []PolyResult
	for _, v := range s.m {
		tmp = append(tmp, v)
	}
	return len(tmp)
}

type IntIntPolyresultMap struct {
	m map[int]IntPolyresultMap
	sync.RWMutex
}

func (s *IntIntPolyresultMap) Init() {
	s.Lock()
	defer s.Unlock()
	s.m = make(map[int]IntPolyresultMap)
}

func (s *IntIntPolyresultMap) Insert(index int, input int, value PolyResult) {
	s.Lock()
	defer s.Unlock()
	es, exi := s.m[index]
	if !exi {
		var newtmp IntPolyresultMap
		newtmp.Init()
		newtmp.Insert(input, value)
		s.m[index] = newtmp
		return
	}
	es.Insert(input, value)
	s.m[index] = es
}

func (s *IntIntPolyresultMap) Get(key int) (IntPolyresultMap, bool) {
	s.Lock()
	defer s.Unlock()
	_, exist := s.m[key]
	if exist {
		return s.m[key], true
	}
	var emp IntPolyresultMap
	return emp, false
}

func (s *IntIntPolyresultMap) GetCount(index int, rindex int, input int) int {
	s.Lock()
	defer s.Unlock()
	es, exi := s.m[index]
	if !exi {
		return 0
	}
	return es.GetCount()
}

func (s *IntIntPolyresultMap) Delete(key int) {
	s.Lock()
	defer s.Unlock()
	delete(s.m, key)
}

type IntPointMap struct {
	m map[int]kyber.Point
	sync.RWMutex
}

func (s *IntPointMap) Init() {
	s.Lock()
	defer s.Unlock()
	s.m = make(map[int]kyber.Point)
}

func (s *IntPointMap) Insert(input int, value kyber.Point) {
	s.Lock()
	defer s.Unlock()
	s.m[input] = value
}

func (s *IntPointMap) Get(key int) (kyber.Point, bool) {
	s.Lock()
	defer s.Unlock()
	_, exist := s.m[key]
	if exist {
		return s.m[key], true
	}
	var emp kyber.Point
	return emp, false
}

func (s *IntPointMap) GetAll() map[int]kyber.Point {
	s.Lock()
	defer s.Unlock()
	return s.m
}
