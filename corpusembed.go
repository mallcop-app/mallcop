// corpusembed.go — the embedded eval scenario corpus.
//
// //go:embed cannot traverse "..", so — exactly like corpus.go
// (operator-decisions) — this embed directive must live in a .go file at the
// repo root: the only directory whose subtree contains exams/scenarios AND is
// package mallcop (the sole production package at the root; hello_test.go is
// the external mallcop_test package, which Go permits to coexist here).
//
// ScenariosFS carries the exact on-disk exams/scenarios subtree at build
// time, EXCLUDING files/dirs whose name begins with "." or "_" — go:embed's
// default directory-embed behavior, which is the SAME leading-underscore skip
// core/eval's disk walker applies by hand (scanCorpus / hasUnderscoreComponent
// in core/eval/corpus.go). That means exams/scenarios/_schema.yaml and the
// exams/scenarios/_test/ subtree are excluded from BOTH the disk scan and this
// embed — so the pinned corpus (count 58 + manifest sha in
// exams/scenarios/corpus.pin, itself embedded since it does not start with
// "_") verifies IDENTICALLY against either source. See core/eval/corpus.go's
// LoadEmbedded and the embed==disk parity test (core/tools/embed_corpus_test.go
// pattern, mirrored for this corpus).
//
// This lets a SHIPPED mallcop binary run `mallcop eval` / exam-detect from the
// compiled-in reference corpus even in a customer deploy repo that carries no
// exams/scenarios directory on disk — core/eval.RepoRoot() finds a repo marker
// (go.mod or .git) belonging to the CUSTOMER repo, which has no corpus; the
// on-disk Load then fails to find exams/scenarios and the caller falls back to
// this embed. An on-disk corpus, when present, always wins over the embed (dev
// edit-and-reload is preserved) — see core/eval/corpus.go's disk-first
// precedence, the same pattern core/tools' operator-decisions loader uses.
package mallcop

import "embed"

// ScenariosFS is the exams/scenarios subtree embedded at build time, rooted at
// the repo root — so paths inside read "exams/scenarios/...", matching the
// relative paths core/eval's disk walker produces from a repoRoot-based
// os.DirFS(repoRoot). Underscore- and dot-prefixed files/dirs are excluded by
// go:embed's directory-embed default (verified equivalent to
// hasUnderscoreComponent's any-depth skip).
//
//go:embed exams/scenarios
var ScenariosFS embed.FS
