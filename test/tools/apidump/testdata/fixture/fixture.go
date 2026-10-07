// Package fixture is apidump's test input: one of each declaration kind.
package fixture

// Const is an exported constant.
const Const = 1

const hidden = 2

// Var is an exported variable.
var Var, other = 1, 2

// Struct has exported and unexported fields.
type Struct struct {
	A, B int
	c    int
}

// Empty is a struct with no exported field.
type Empty struct{ x int }

// Iface is an interface.
type Iface interface {
	M()
	N()
}

// Named is a defined non-struct type.
type Named string

// Alias is a type alias: it carries Named's method set without declaring
// any FuncDecl of its own.
type Alias = Named

// Generic is a generic type.
type Generic[T any] struct{ v T }

type unexported struct{}

// Func is an exported function.
func Func() {}

func helper() {}

// Method is on a pointer receiver.
func (s *Struct) Method() {}

// Value is on a value receiver.
func (Named) Value() {}

// Get is on a generic receiver.
func (g *Generic[T]) Get() T { return g.v }

// Exported is a method of an unexported type, which is not API.
func (unexported) Exported() {}

func (s *Struct) hidden() {}
