package initcmd

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

//go:embed templates/workflow.yml templates/fendix-ignore.txt templates/fendix-yaml.txt
var templates embed.FS

// Options controls Run's behavior. Zero-value defaults are sensible.
type Options struct {
	// RootDir is the project root where files will be written. Defaults
	// to the process working directory when empty.
	RootDir string

	// Force overwrites existing files. Without it, Run refuses to
	// clobber any of the target paths and returns ErrFileExists.
	Force bool

	// Print writes generated content to Out instead of disk. Useful for
	// previewing what `fendix init` would do before committing.
	Print bool

	// Out is where status lines and (when Print is true) generated
	// content go. Defaults to os.Stdout when nil.
	Out io.Writer
}

// File describes one file that init will write. Path is relative to
// the project root.
type File struct {
	Path    string
	Content []byte
}

// ErrFileExists is returned when a target file already exists and
// Force is not set. The error wraps the conflicting path.
type ErrFileExists struct {
	Path string
}

func (e *ErrFileExists) Error() string {
	return fmt.Sprintf("refusing to overwrite existing file: %s (rerun with --force to overwrite)", e.Path)
}

// Run executes `fendix init` end-to-end: detect → plan → write. It
// emits human-readable status lines to Options.Out. On success, the
// project will have a committable CI workflow + a starter ignore file.
//
// Run returns *ErrFileExists when one of the target files already
// exists and --force was not set. Other errors are filesystem errors
// (mkdir, write) wrapped with context.
func Run(opts Options) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	root := opts.RootDir
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
		root = wd
	}

	det := Detect(root)
	fmt.Fprintf(opts.Out, "✓ Detected: %s\n", det.SummaryLine())

	files, err := planFiles()
	if err != nil {
		return err
	}

	if opts.Print {
		return printFiles(opts.Out, files)
	}

	// Pre-flight: check for existing files unless --force is set. Doing
	// this BEFORE writing any file avoids the half-written-init state
	// where one file lands and a later one fails — atomicity in spirit.
	if !opts.Force {
		for _, f := range files {
			abs := filepath.Join(root, f.Path)
			if _, err := os.Stat(abs); err == nil {
				return &ErrFileExists{Path: f.Path}
			}
		}
	}

	for _, f := range files {
		abs := filepath.Join(root, f.Path)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return fmt.Errorf("creating dir for %s: %w", f.Path, err)
		}
		if err := os.WriteFile(abs, f.Content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", f.Path, err)
		}
		fmt.Fprintf(opts.Out, "✓ Wrote %s\n", f.Path)
	}

	fmt.Fprintln(opts.Out)
	fmt.Fprintln(opts.Out, "Next steps:")
	fmt.Fprintln(opts.Out, "  git add .github/workflows/fendix.yml .fendix.yaml .fendix-ignore")
	fmt.Fprintln(opts.Out, "  git commit -m \"Add Fendix security scanning\"")
	fmt.Fprintln(opts.Out)
	fmt.Fprintln(opts.Out, "Run a scan now:")
	fmt.Fprintln(opts.Out, "  fendix scan --url https://api.example.com")

	return nil
}

func planFiles() ([]File, error) {
	workflow, err := templates.ReadFile("templates/workflow.yml")
	if err != nil {
		return nil, fmt.Errorf("reading embedded workflow template: %w", err)
	}
	policy, err := templates.ReadFile("templates/fendix-yaml.txt")
	if err != nil {
		return nil, fmt.Errorf("reading embedded policy template: %w", err)
	}
	ignore, err := templates.ReadFile("templates/fendix-ignore.txt")
	if err != nil {
		return nil, fmt.Errorf("reading embedded ignore template: %w", err)
	}
	return []File{
		{Path: ".github/workflows/fendix.yml", Content: workflow},
		{Path: ".fendix.yaml", Content: policy},
		{Path: ".fendix-ignore", Content: ignore},
	}, nil
}

func printFiles(w io.Writer, files []File) error {
	for i, f := range files {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "──── %s ────\n", f.Path)
		if _, err := w.Write(f.Content); err != nil {
			return fmt.Errorf("writing preview: %w", err)
		}
	}
	return nil
}
