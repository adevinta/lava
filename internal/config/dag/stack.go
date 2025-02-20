// Copyright 2025 Adevinta

package dag

import "errors"

// Stack is a generic stack implementation.
type Stack[T any] struct {
	elements []T
}

// Push adds a new element to the top of the stack.
func (s *Stack[T]) Push(element T) {
	s.elements = append(s.elements, element)
}

// IsEmpty returns a bool to indicate if the stack is empty.
func (s *Stack[T]) IsEmpty() bool {
	return len(s.elements) == 0
}

// Pop rads and removes an element from the stack or
// returns an error if the stack is empty.
func (s *Stack[T]) Pop() (*T, error) {
	if s.IsEmpty() {
		return nil, errors.New("cannot pop from empty stack")
	}
	// the last element is the one to read.
	top := s.elements[len(s.elements)-1]
	// drop read element.
	s.elements = s.elements[:len(s.elements)-1]
	return &top, nil
}
