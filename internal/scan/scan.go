package scan

import (
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/umeraamir69/secsentry/internal/classify"
	"github.com/umeraamir69/secsentry/internal/detect"
	"github.com/umeraamir69/secsentry/internal/gitutil"
	"github.com/umeraamir69/secsentry/internal/model"
	"github.com/umeraamir69/secsentry/internal/verify"
)

const maxFileBytes = 1_000_000

type Report struct {
	Findings       []model.Finding
	FilesScanned   int
	BlobsScanned   int
	CommitsScanned int
	Repo           string
	Allowlisted    int
}

func (r Report) Secrets() []Secret { return Group(r.Findings) }

func (r Report) Counts() map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, s := range r.Secrets() {
		k := strings.ToLower(s.Severity)
		if _, ok := out[k]; ok {
			out[k]++
		}
	}
	return out
}

func (r Report) ShouldFail(failOn string) bool {
	threshold := model.Rank(failOn)
	if threshold == 0 {
		threshold = 3
	}
	for _, f := range r.Findings {
		if model.Rank(f.Severity) >= threshold {
			return true
		}
	}
	return false
}

type context struct {
	findings    []model.Finding
	seen        map[string]bool
	headOIDs    map[string]struct{}
	allowed     []string
	files       int
	blobs       int
	commits     int
	allowlisted int
}

func newContext(repo string) *context {
	return &context{
		seen:    map[string]bool{},
		allowed: loadAllowlist(repo),
	}
}

func (c *context) add(f model.Finding) {
	if isAllowlisted(f.Fingerprint, c.allowed) {
		c.allowlisted++
		return
	}
	key := f.Fingerprint + "\x00" + f.Path + "\x00" + itoa(f.Line)
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.findings = append(c.findings, f)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func findingsFromText(path, text, blobOID string) []model.Finding {
	var found []model.Finding
	seen := map[string]bool{}

	consider := func(scanText, scanPath string, extra []string, lineOver, colOver int, useOver bool) {
		for _, hit := range detect.Detect(scanText) {
			ok := verify.OK(hit.Type, hit.Secret)
			dec := classify.Classify(scanPath, hit.Type, hit.Secret, ok)
			if !dec.Keep {
				continue
			}
			line, col := hit.Line, hit.Column
			if useOver {
				line, col = lineOver, colOver
			}
			key := hit.Secret + "\x00" + scanPath + "\x00" + itoa(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			okv := ok
			found = append(found, model.Finding{
				SecretType:   hit.Type,
				Severity:     hit.Severity,
				Confidence:   dec.Confidence,
				Path:         scanPath,
				Line:         line,
				Column:       col,
				Masked:       model.Mask(hit.Secret),
				Fingerprint:  model.Fingerprint(hit.Secret),
				BlobOID:      blobOID,
				StructuralOK: &okv,
				Entropy:      hit.Entropy,
				Why:          append(append([]string{}, dec.Why...), extra...),
			})
		}
	}

	consider(text, path, nil, 0, 0, false)
	for _, chunk := range iterDecoded(text) {
		tag := "decoded:" + strings.Join(chunk.Encodings, "+")
		consider(chunk.Text, path, []string{tag}, chunk.Line, chunk.Col, true)
	}
	return found
}

func asText(data []byte) string {
	if len(data) == 0 || len(data) > maxFileBytes || bytesContainNUL(data) {
		return ""
	}
	if !utf8.Valid(data) {
		return ""
	}
	return string(data)
}

func readLimited(path string, limit int) ([]byte, bool) {
	st, err := os.Stat(path)
	if err != nil || st.Size() > int64(limit) {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func scanWorkingTree(ctx *context, root string) {
	ig := loadIgnores(root)
	for _, rel := range candidatePaths(root) {
		if skippedPath(rel) || ig.match(rel) {
			continue
		}
		full := filepath.Join(root, rel)
		data, ok := readLimited(full, maxArchiveBytes)
		if !ok {
			data, ok = readLimited(full, maxFileBytes)
		}
		if !ok {
			continue
		}
		ctx.files++
		if looksArchive(rel, data) {
			for _, pair := range walkArchive(data, rel, 1) {
				for _, f := range findingsFromText(pair[0], pair[1], "") {
					f.Source = "working-tree"
					ctx.add(f)
				}
			}
			continue
		}
		if len(data) > maxFileBytes {
			continue
		}
		if text := asText(data); text != "" {
			for _, f := range findingsFromText(rel, text, "") {
				f.Source = "working-tree"
				ctx.add(f)
			}
		}
	}
}

func scanStaged(ctx *context, root string) {
	pairs, err := gitutil.Staged(root)
	if err != nil {
		return
	}
	for _, p := range pairs {
		ctx.files++
		for _, f := range findingsFromText(p[0], p[1], "") {
			f.Source = "staged"
			ctx.add(f)
		}
	}
}

func hitsForBlob(oid string, data []byte, name string) []model.Finding {
	var hits []model.Finding
	if text := asText(data); text != "" || (len(data) <= maxFileBytes && utf8.Valid(data) && !bytesContainNUL(data)) {
		if t := string(data); utf8.Valid(data) && !bytesContainNUL(data) && len(data) <= maxFileBytes {
			hits = append(hits, findingsFromText(name, t, oid)...)
		}
	}
	if looksArchive(name, data) {
		for _, pair := range walkArchive(data, name, 1) {
			hits = append(hits, findingsFromText(pair[0], pair[1], oid)...)
		}
	}
	return hits
}

func scanHistory(ctx *context, root string) {
	contents, refs, err := gitutil.UniqueBlobs(root)
	if err != nil {
		return
	}
	ctx.blobs += len(contents)
	commits := map[string]struct{}{}
	for _, r := range refs {
		commits[r.Commit] = struct{}{}
	}
	ctx.commits += len(commits)

	blobHits := map[string][]model.Finding{}
	for oid, data := range contents {
		blobHits[oid] = hitsForBlob(oid, data, "(blob)")
	}
	for _, ref := range refs {
		for _, f := range blobHits[ref.OID] {
			path := f.Path
			if strings.HasPrefix(path, "(blob)!") {
				path = ref.Path + "!" + strings.SplitN(path, "!", 2)[1]
			} else if path == "(blob)" {
				path = ref.Path
			}
			f.Path = path
			f.Commit = ref.Commit
			f.Author = ref.Author
			f.AuthorEmail = ref.Email
			f.Timestamp = ref.Timestamp
			f.Source = "history"
			ctx.add(f)
		}
	}
}

type Options struct {
	History  bool
	Staged   bool
	Severity string
	Types    []string
}

func Run(repo string, opt Options) (Report, error) {
	abs, err := filepath.Abs(repo)
	if err != nil {
		return Report{}, err
	}
	ctx := newContext(abs)
	if opt.Staged {
		scanStaged(ctx, abs)
	} else {
		scanWorkingTree(ctx, abs)
		if opt.History && gitutil.IsRepo(abs) {
			ctx.headOIDs = gitutil.HeadBlobOIDs(abs)
			scanHistory(ctx, abs)
			for i := range ctx.findings {
				if ctx.findings[i].BlobOID != "" {
					_, ok := ctx.headOIDs[ctx.findings[i].BlobOID]
					ctx.findings[i].StillInHead = &ok
				}
			}
		}
	}

	findings := ctx.findings
	if opt.Severity != "" {
		th := model.Rank(opt.Severity)
		var keep []model.Finding
		for _, f := range findings {
			if model.Rank(f.Severity) >= th {
				keep = append(keep, f)
			}
		}
		findings = keep
	}
	if len(opt.Types) > 0 {
		var keep []model.Finding
		for _, f := range findings {
			low := strings.ToLower(f.SecretType)
			for _, w := range opt.Types {
				if strings.Contains(low, strings.ToLower(w)) {
					keep = append(keep, f)
					break
				}
			}
		}
		findings = keep
	}
	return Report{
		Findings:       findings,
		FilesScanned:   ctx.files,
		BlobsScanned:   ctx.blobs,
		CommitsScanned: ctx.commits,
		Repo:           abs,
		Allowlisted:    ctx.allowlisted,
	}, nil
}
