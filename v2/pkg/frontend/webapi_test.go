package frontend

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"

	"github.com/glauth/glauth/v2/pkg/assets"
)

// TestAPI is a small test to make sure that behavior didn't change for the
// worse when switching over to the go1.16+ "embed" package from go-bindata.
func TestAPI(t *testing.T) {
	tt := []struct {
		Name  string
		Path  string
		Check func(testing.TB, *http.Response)
	}{
		{
			Name: "Root",
			Path: "/",
			Check: func(t testing.TB, res *http.Response) {
				if res.StatusCode != http.StatusOK {
					t.Errorf("unexpected response: %v", res.Status)
					return
				}
				h := sha256.New()
				if _, err := io.Copy(h, res.Body); err != nil {
					t.Error(err)
				}
				if got, want := h.Sum(nil), mkDigest(t, "index.html"); !bytes.Equal(got, want) {
					t.Errorf("bad digest: got: %x, want %x", got, want)
				}
			},
		},
		{
			Name: "NotFound",
			Path: "/glauth.js",
			Check: func(t testing.TB, res *http.Response) {
				if res.StatusCode == http.StatusNotFound {
					return
				}
				t.Errorf("unexpected response: %v", res.Status)
			},
		},
		{
			Name: "Content-Type",
			Path: "/assets/glauth.js",
			Check: func(t testing.TB, res *http.Response) {
				if res.StatusCode != http.StatusOK {
					t.Errorf("unexpected response: %v", res.Status)
				}
				if got, want := res.Header.Get("Content-Type"), `application/javascript`; got != want {
					t.Errorf("bad content-type: got: %q, want %q", got, want)
				}
				h := sha256.New()
				if _, err := io.Copy(h, res.Body); err != nil {
					t.Error(err)
				}
				if got, want := h.Sum(nil), mkDigest(t, "glauth.js"); !bytes.Equal(got, want) {
					t.Errorf("bad digest: got: %x, want %x", got, want)
				}
			},
		},
		{
			Name: "Content-Type",
			Path: "/assets/glauth.css",
			Check: func(t testing.TB, res *http.Response) {
				if res.StatusCode != http.StatusOK {
					t.Errorf("unexpected response: %v", res.Status)
				}
				// This isn't exactly the same, it adds a charset argument.
				if got, want := res.Header.Get("Content-Type"), `text/css; charset=utf-8`; got != want {
					t.Errorf("bad content-type: got: %q, want %q", got, want)
				}
				h := sha256.New()
				if _, err := io.Copy(h, res.Body); err != nil {
					t.Error(err)
				}
				if got, want := h.Sum(nil), mkDigest(t, "glauth.css"); !bytes.Equal(got, want) {
					t.Errorf("bad digest: got: %x, want %x", got, want)
				}
			},
		},
	}

	mux := http.NewServeMux()
	register(mux, logr.Discard())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.URL+tc.Path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			tc.Check(t, res)
		})
	}

}

func mkDigest(t testing.TB, path string) []byte {
	f, err := assets.Content.Open(path)
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Error(err)
	}
	return h.Sum(nil)
}
