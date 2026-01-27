package resolver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestNPMClient(handler http.HandlerFunc) (*NPMClient, func()) {
	server := httptest.NewServer(handler)
	client := &NPMClient{
		baseURL:    server.URL,
		httpClient: server.Client(),
	}
	return client, server.Close
}

func TestNPMClient_GetPackageInfo_Success(t *testing.T) {
	info := NPMPackageInfo{
		Name:        "lodash",
		Description: "Lodash library",
		DistTags:    map[string]string{"latest": "4.17.21"},
		Versions: map[string]NPMVersionInfo{
			"4.17.21": {Name: "lodash", Version: "4.17.21"},
		},
		Maintainers: []NPMMaintainer{{Name: "jdalton", Email: "john@example.com"}},
	}

	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(info)
	})
	defer cleanup()

	result, err := client.GetPackageInfo("lodash")
	if err != nil {
		t.Fatalf("GetPackageInfo returned error: %v", err)
	}
	if result.Name != "lodash" {
		t.Errorf("Name = %q, want %q", result.Name, "lodash")
	}
	if result.DistTags["latest"] != "4.17.21" {
		t.Errorf("latest tag = %q, want %q", result.DistTags["latest"], "4.17.21")
	}
	if len(result.Maintainers) != 1 {
		t.Errorf("Maintainers count = %d, want 1", len(result.Maintainers))
	}
}

func TestNPMClient_GetPackageInfo_NotFound(t *testing.T) {
	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	_, err := client.GetPackageInfo("nonexistent-package-xyz")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestNPMClient_GetPackageInfo_ServerError(t *testing.T) {
	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer cleanup()

	_, err := client.GetPackageInfo("lodash")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestNPMClient_GetPackageInfo_InvalidJSON(t *testing.T) {
	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json{{{"))
	})
	defer cleanup()

	_, err := client.GetPackageInfo("lodash")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestNPMClient_GetVersionInfo_Success(t *testing.T) {
	versionInfo := NPMVersionInfo{
		Name:    "express",
		Version: "4.18.2",
		Scripts: map[string]string{"start": "node server.js"},
		Dependencies: map[string]string{
			"body-parser": "1.20.1",
		},
		Dist: NPMDist{
			Tarball:   "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
			Shasum:    "abc123",
			Integrity: "sha512-abc",
		},
	}

	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/express/4.18.2" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(versionInfo)
	})
	defer cleanup()

	result, err := client.GetVersionInfo("express", "4.18.2")
	if err != nil {
		t.Fatalf("GetVersionInfo returned error: %v", err)
	}
	if result.Name != "express" {
		t.Errorf("Name = %q, want %q", result.Name, "express")
	}
	if result.Version != "4.18.2" {
		t.Errorf("Version = %q, want %q", result.Version, "4.18.2")
	}
	if result.Dependencies["body-parser"] != "1.20.1" {
		t.Errorf("body-parser dep = %q, want %q", result.Dependencies["body-parser"], "1.20.1")
	}
	if result.Dist.Shasum != "abc123" {
		t.Errorf("Dist.Shasum = %q, want %q", result.Dist.Shasum, "abc123")
	}
}

func TestNPMClient_GetVersionInfo_NotFound(t *testing.T) {
	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	_, err := client.GetVersionInfo("express", "99.99.99")
	if err == nil {
		t.Error("expected error for 404 version")
	}
}

func TestNPMClient_GetLatestVersion(t *testing.T) {
	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash/latest" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(NPMVersionInfo{
			Name:    "lodash",
			Version: "4.17.21",
		})
	})
	defer cleanup()

	version, err := client.GetLatestVersion("lodash")
	if err != nil {
		t.Fatalf("GetLatestVersion returned error: %v", err)
	}
	if version != "4.17.21" {
		t.Errorf("latest version = %q, want %q", version, "4.17.21")
	}
}

func TestNPMClient_GetLatestVersion_NoLatestTag(t *testing.T) {
	client, cleanup := newTestNPMClient(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	_, err := client.GetLatestVersion("lodash")
	if err == nil {
		t.Error("expected error when no latest tag exists")
	}
}

func TestHasPostInstallScript(t *testing.T) {
	tests := []struct {
		name    string
		scripts map[string]string
		want    bool
	}{
		{"postinstall", map[string]string{"postinstall": "echo hi"}, true},
		{"preinstall", map[string]string{"preinstall": "echo hi"}, true},
		{"install", map[string]string{"install": "echo hi"}, true},
		{"preuninstall", map[string]string{"preuninstall": "echo hi"}, true},
		{"postuninstall", map[string]string{"postuninstall": "echo hi"}, true},
		{"start only", map[string]string{"start": "node index.js"}, false},
		{"test only", map[string]string{"test": "jest"}, false},
		{"empty", map[string]string{}, false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &NPMVersionInfo{Scripts: tt.scripts}
			got := v.HasPostInstallScript()
			if got != tt.want {
				t.Errorf("HasPostInstallScript() = %v, want %v", got, tt.want)
			}
		})
	}
}
