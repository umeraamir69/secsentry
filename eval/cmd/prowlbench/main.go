// Command prowlbench scores SecSentry on ProwlBench cases (snippet-level).
// Detection = at least one kept finding in the snippet (same rule as Lercas/prowlbench).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/umeraamir69/secsentry/internal/scan"
)

type Case struct {
	ID     string `json:"id"`
	Text   string `json:"text"`
	Source string `json:"source"`
}

var ext = map[string]string{
	"code": ".py", "jira": ".md", "confluence": ".md", "log": ".log", "slack": ".txt",
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	out := []string{}
	n := 0
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var c Case
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			fmt.Fprintf(os.Stderr, "bad json: %v\n", err)
			os.Exit(1)
		}
		path := c.ID + ext[c.Source]
		if path == c.ID {
			path = c.ID + ".txt"
		}
		if len(scan.FindingsFromText(path, c.Text)) > 0 {
			out = append(out, c.ID)
		}
		n++
		if n%5000 == 0 {
			fmt.Fprintf(os.Stderr, "secsentry scored %d cases\n", n)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
}
