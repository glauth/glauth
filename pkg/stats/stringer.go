package stats

type Stringer string

func (s Stringer) String() string { return "\"" + string(s) + "\"" }
