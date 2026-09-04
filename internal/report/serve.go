package report

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
)

const host = "127.0.0.1"

func Serve(p Payload, port int, openBrowser bool) error {
	htmlBody := []byte(Render(p))
	raw, _ := json.MarshalIndent(p, "", "  ")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(htmlBody)
	})
	mux.HandleFunc("/report.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s", ln.Addr().String())
	fmt.Printf("SecSentry dashboard  %s\n", url)
	fmt.Println("Loopback only. Secrets are masked. Ctrl-C to stop.")
	if openBrowser {
		_ = openURL(url)
	}
	return http.Serve(ln, mux)
}

func openURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
