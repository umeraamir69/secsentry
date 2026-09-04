package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/umeraamir69/secsentry/internal/hooks"
	"github.com/umeraamir69/secsentry/internal/report"
	"github.com/umeraamir69/secsentry/internal/scan"
	"github.com/umeraamir69/secsentry/internal/version"
)

const usage = `secsentry — find leaked secrets in a Git working tree and its history.

Secrets are always masked. SecSentry never sends a credential to a vendor API.

Usage:
  secsentry scan [path] [flags]
  secsentry serve [path] [flags]
  secsentry install-hook [path]
  secsentry uninstall-hook [path]

Scan flags:
  --history          scan every commit (blob-deduped)
  --staged           scan git diff --cached only
  --severity LEVEL   only report at or above this severity
  --type NAME        only this detector family (repeatable)
  --format FMT       text | json | html | sarif  (default text)
  --fail-on LEVEL    exit 1 at this severity (default high)
  --output, -o PATH  write the report to this path
  --no-cache         do not write .secsentry/last-scan.json

Serve flags:
  --port N           dashboard port (default 8765)
  --no-browser       do not open a browser
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if argv[0] == "--version" || argv[0] == "-version" {
		fmt.Printf("secsentry %s\n", version.Version)
		return 0
	}
	cmd := argv[0]
	args := argv[1:]
	switch cmd {
	case "scan":
		return cmdScan(args)
	case "serve":
		return cmdServe(args)
	case "install-hook":
		path := "."
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			path = args[0]
		}
		abs, _ := filepath.Abs(path)
		if err := hooks.Install(abs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "uninstall-hook":
		path := "."
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			path = args[0]
		}
		abs, _ := filepath.Abs(path)
		if err := hooks.Uninstall(abs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

type scanFlags struct {
	fs       *flag.FlagSet
	history  *bool
	staged   *bool
	severity *string
	failOn   *string
	format   *string
	output   *string
	noCache  *bool
	port     *int
	noBrowse *bool
	types    *stringList
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

var valuedFlags = map[string]bool{
	"--severity": true, "--type": true, "--format": true, "--fail-on": true,
	"--output": true, "-o": true, "--port": true,
}

func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name, _, cut := strings.Cut(a, "=")
			if !cut && valuedFlags[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func parseScan(name string, args []string, serve bool) (scanFlags, string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	args = reorderFlags(args)
	f := scanFlags{
		fs:       fs,
		history:  fs.Bool("history", false, "scan every commit"),
		staged:   fs.Bool("staged", false, "scan staged files only"),
		severity: fs.String("severity", "", "minimum severity"),
		failOn:   fs.String("fail-on", "high", "exit 1 at this severity"),
		format:   fs.String("format", "text", "text|json|html|sarif"),
		output:   fs.String("output", "", "write report to path"),
		noCache:  fs.Bool("no-cache", false, "do not write last-scan.json"),
		types:    &stringList{},
	}
	fs.Var(f.types, "type", "detector family (repeatable)")
	fs.StringVar(f.output, "o", "", "write report to path")
	if serve {
		f.port = fs.Int("port", 8765, "dashboard port")
		f.noBrowse = fs.Bool("no-browser", false, "do not open a browser")
	}
	if err := fs.Parse(args); err != nil {
		return f, "", err
	}
	path := fs.Arg(0)
	if path == "" {
		path = "."
	}
	return f, path, nil
}

func doScan(f scanFlags, path string) (string, scan.Report, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", scan.Report{}, err
	}
	rep, err := scan.Run(abs, scan.Options{
		History:  *f.history,
		Staged:   *f.staged,
		Severity: *f.severity,
		Types:    []string(*f.types),
	})
	return abs, rep, err
}

func formatReport(rep scan.Report, format string) string {
	switch format {
	case "json":
		return report.JSON(rep)
	case "html":
		return report.Render(report.Build(rep))
	case "sarif":
		return report.SARIF(rep)
	default:
		return ""
	}
}

func writeCache(repo string, payload report.Payload) {
	dir := filepath.Join(repo, ".secsentry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "last-scan.json"), b, 0o644)
}

func cmdScan(args []string) int {
	f, path, err := parseScan("scan", args, false)
	if err != nil {
		return 2
	}
	repo, rep, err := doScan(f, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	payload := report.Build(rep)
	if *f.output != "" {
		out := *f.output
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		body := formatReport(rep, *f.format)
		if body == "" {
			body = report.JSON(rep)
		}
		if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("Wrote %s\n", out)
		report.Print(rep)
	} else if *f.format == "json" {
		fmt.Println(report.JSON(rep))
	} else if *f.format == "html" {
		fmt.Print(report.Render(payload))
	} else if *f.format == "sarif" {
		fmt.Println(report.SARIF(rep))
	} else {
		report.Print(rep)
	}
	if !*f.noCache && !*f.staged {
		writeCache(repo, payload)
	}
	if rep.ShouldFail(*f.failOn) {
		return 1
	}
	return 0
}

func cmdServe(args []string) int {
	f, path, err := parseScan("serve", args, true)
	if err != nil {
		return 2
	}
	_, rep, err := doScan(f, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	open := true
	if f.noBrowse != nil {
		open = !*f.noBrowse
	}
	port := 8765
	if f.port != nil {
		port = *f.port
	}
	if err := report.Serve(report.Build(rep), port, open); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
