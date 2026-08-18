package engine

// BuildDefaultRegistry constructs a registry and invokes package Register funcs.
// This is the only acceptable central wiring — no protocol switch.
func BuildDefaultRegistry(registers ...RegisterFunc) *Registry {
	r := NewRegistry()
	for _, reg := range registers {
		if reg != nil {
			reg(r)
		}
	}
	return r
}
