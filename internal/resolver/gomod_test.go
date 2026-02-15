package resolver

import (
	"testing"
)

func TestParseGoMod(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected *GoPackage
	}{
		{
			name: "simple module",
			content: `module github.com/example/project

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/go-sql-driver/mysql v1.7.1
)
`,
			expected: &GoPackage{
				Path: "github.com/example/project",
				Dependencies: []string{
					"github.com/gin-gonic/gin",
					"github.com/go-sql-driver/mysql",
				},
				Replace: make(map[string]string),
				Exclude: []string{},
				Retract: []string{},
			},
		},
		{
			name: "module with indirect dependencies",
			content: `module github.com/example/project

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/go-sql-driver/mysql v1.7.1 // indirect
)
`,
			expected: &GoPackage{
				Path: "github.com/example/project",
				Dependencies: []string{
					"github.com/gin-gonic/gin",
				},
				Indirect: []string{
					"github.com/go-sql-driver/mysql",
				},
				Replace: make(map[string]string),
				Exclude: []string{},
				Retract: []string{},
			},
		},
		{
			name: "module with replace directive",
			content: `module github.com/example/project

go 1.21

require github.com/gin-gonic/gin v1.9.1

replace github.com/gin-gonic/gin => github.com/custom/gin v1.9.1-custom
`,
			expected: &GoPackage{
				Path: "github.com/example/project",
				Dependencies: []string{
					"github.com/gin-gonic/gin",
				},
				Replace: map[string]string{
					"github.com/gin-gonic/gin": "github.com/custom/gin v1.9.1-custom",
				},
				Exclude: []string{},
				Retract: []string{},
			},
		},
		{
			name: "module with exclude directive",
			content: `module github.com/example/project

go 1.21

require github.com/gin-gonic/gin v1.9.1

exclude github.com/gin-gonic/gin v1.9.0
`,
			expected: &GoPackage{
				Path: "github.com/example/project",
				Dependencies: []string{
					"github.com/gin-gonic/gin",
				},
				Replace: make(map[string]string),
				Exclude: []string{
					"github.com/gin-gonic/gin v1.9.0",
				},
				Retract: []string{},
			},
		},
		{
			name: "module with retract directive",
			content: `module github.com/example/project

go 1.21

require github.com/gin-gonic/gin v1.9.1

retract v1.9.0
`,
			expected: &GoPackage{
				Path: "github.com/example/project",
				Dependencies: []string{
					"github.com/gin-gonic/gin",
				},
				Replace: make(map[string]string),
				Exclude: []string{},
				Retract: []string{
					"v1.9.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseGoMod(tt.content)
			if err != nil {
				t.Errorf("ParseGoMod() error = %v", err)
				return
			}

			// Check module path
			if result.Path != tt.expected.Path {
				t.Errorf("ParseGoMod() path = %v, want %v", result.Path, tt.expected.Path)
			}

			// Check dependencies
			if len(result.Dependencies) != len(tt.expected.Dependencies) {
				t.Errorf("ParseGoMod() dependencies = %v, want %v", result.Dependencies, tt.expected.Dependencies)
				return
			}
			for i, dep := range result.Dependencies {
				if dep != tt.expected.Dependencies[i] {
					t.Errorf("ParseGoMod() dependencies[%d] = %v, want %v", i, dep, tt.expected.Dependencies[i])
				}
			}

			// Check indirect dependencies
			if len(result.Indirect) != len(tt.expected.Indirect) {
				t.Errorf("ParseGoMod() indirect = %v, want %v", result.Indirect, tt.expected.Indirect)
				return
			}
			for i, dep := range result.Indirect {
				if dep != tt.expected.Indirect[i] {
					t.Errorf("ParseGoMod() indirect[%d] = %v, want %v", i, dep, tt.expected.Indirect[i])
				}
			}

			// Check replace directives
			if len(result.Replace) != len(tt.expected.Replace) {
				t.Errorf("ParseGoMod() replace = %v, want %v", result.Replace, tt.expected.Replace)
				return
			}
			for old, new := range tt.expected.Replace {
				if result.Replace[old] != new {
					t.Errorf("ParseGoMod() replace[%s] = %v, want %v", old, result.Replace[old], new)
				}
			}

			// Check exclude directives
			if len(result.Exclude) != len(tt.expected.Exclude) {
				t.Errorf("ParseGoMod() exclude = %v, want %v", result.Exclude, tt.expected.Exclude)
				return
			}
			for i, exclude := range result.Exclude {
				if exclude != tt.expected.Exclude[i] {
					t.Errorf("ParseGoMod() exclude[%d] = %v, want %v", i, exclude, tt.expected.Exclude[i])
				}
			}

			// Check retract directives
			if len(result.Retract) != len(tt.expected.Retract) {
				t.Errorf("ParseGoMod() retract = %v, want %v", result.Retract, tt.expected.Retract)
				return
			}
			for i, retract := range result.Retract {
				if retract != tt.expected.Retract[i] {
					t.Errorf("ParseGoMod() retract[%d] = %v, want %v", i, retract, tt.expected.Retract[i])
				}
			}
		})
	}
}

func TestParseGoSum(t *testing.T) {
	content := `github.com/gin-gonic/gin v1.9.1 h1:BN9v673w0cjqn27ERIknOjx7VzijMjEoB0FtF8gUW3Q=
github.com/gin-gonic/gin v1.9.1/go.mod h1:9lE1iN5E6tWxVU4s4xGzFO3i4Pv/fKet2g0h2D4mWmE=
github.com/go-sql-driver/mysql v1.7.1 h1:xxzZk92f48j4R9E79B76vE000000000000000000000=
github.com/go-sql-driver/mysql v1.7.1/go.mod h1:0000000000000000000000000000000000000000=
`

	expected := map[string]string{
		"github.com/gin-gonic/gin v1.9.1":          "h1:BN9v673w0cjqn27ERIknOjx7VzijMjEoB0FtF8gUW3Q=",
		"github.com/gin-gonic/gin v1.9.1/go.mod":   "h1:9lE1iN5E6tWxVU4s4xGzFO3i4Pv/fKet2g0h2D4mWmE=",
		"github.com/go-sql-driver/mysql v1.7.1":    "h1:xxzZk92f48j4R9E79B76vE000000000000000000000=",
		"github.com/go-sql-driver/mysql v1.7.1/go.mod": "h1:0000000000000000000000000000000000000000=",
	}

	result := ParseGoSum(content)

	if len(result) != len(expected) {
		t.Errorf("ParseGoSum() length = %d, want %d", len(result), len(expected))
		return
	}

	for module, checksum := range expected {
		if result[module] != checksum {
			t.Errorf("ParseGoSum() [%s] = %v, want %v", module, result[module], checksum)
		}
	}
}

func TestGetDirectDependencies(t *testing.T) {
	pkg := &GoPackage{
		Path: "github.com/example/project",
		Dependencies: []string{
			"github.com/gin-gonic/gin",
			"github.com/go-sql-driver/mysql",
		},
		Replace: map[string]string{
			"github.com/gin-gonic/gin": "github.com/custom/gin v1.9.1-custom",
		},
	}

	expected := []string{
		"github.com/go-sql-driver/mysql",
	}

	result := GetDirectDependencies(pkg)

	if len(result) != len(expected) {
		t.Errorf("GetDirectDependencies() length = %d, want %d", len(result), len(expected))
		return
	}

	for i, dep := range result {
		if dep != expected[i] {
			t.Errorf("GetDirectDependencies() [%d] = %v, want %v", i, dep, expected[i])
		}
	}
}

func TestGetIndirectDependencies(t *testing.T) {
	pkg := &GoPackage{
		Path: "github.com/example/project",
		Indirect: []string{
			"github.com/gin-gonic/gin",
			"github.com/go-sql-driver/mysql",
		},
		Replace: map[string]string{
			"github.com/gin-gonic/gin": "github.com/custom/gin v1.9.1-custom",
		},
	}

	expected := []string{
		"github.com/go-sql-driver/mysql",
	}

	result := GetIndirectDependencies(pkg)

	if len(result) != len(expected) {
		t.Errorf("GetIndirectDependencies() length = %d, want %d", len(result), len(expected))
		return
	}

	for i, dep := range result {
		if dep != expected[i] {
			t.Errorf("GetIndirectDependencies() [%d] = %v, want %v", i, dep, expected[i])
		}
	}
}