package main

type stringSet map[string]struct{}

func (s stringSet) Add(v string) {
	s[v] = struct{}{}
}

func (s stringSet) Has(v string) bool {
	_, ok := s[v]
	return ok
}

func (s stringSet) Remove(v string) {
	delete(s, v)
}
