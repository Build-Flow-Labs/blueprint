package setup

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// prompter wraps interactive input for the wizard.
type prompter struct {
	scanner *bufio.Scanner
	out     io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	return &prompter{
		scanner: bufio.NewScanner(in),
		out:     out,
	}
}

// ask prints a prompt and reads one line of input.
func (p *prompter) ask(prompt string) string {
	fmt.Fprintf(p.out, "%s ", prompt)
	if p.scanner.Scan() {
		return strings.TrimSpace(p.scanner.Text())
	}
	return ""
}

// askDefault prints a prompt with a default value shown in brackets.
func (p *prompter) askDefault(prompt, defaultVal string) string {
	answer := p.ask(fmt.Sprintf("%s [%s]:", prompt, defaultVal))
	if answer == "" {
		return defaultVal
	}
	return answer
}

// askYesNo prints a y/n prompt and returns true for yes.
func (p *prompter) askYesNo(prompt string, defaultYes bool) bool {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	answer := strings.ToLower(p.ask(fmt.Sprintf("%s %s:", prompt, suffix)))
	switch answer {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// askChoice prints numbered options and returns the selected 0-based index.
func (p *prompter) askChoice(prompt string, options []string) int {
	fmt.Fprintln(p.out, prompt)
	for i, opt := range options {
		fmt.Fprintf(p.out, "  [%d] %s\n", i+1, opt)
	}
	for {
		answer := p.ask("Choice:")
		n, err := strconv.Atoi(answer)
		if err == nil && n >= 1 && n <= len(options) {
			return n - 1
		}
		fmt.Fprintf(p.out, "Please enter a number between 1 and %d.\n", len(options))
	}
}

// askMultiSelect prints numbered options and lets user select multiple (comma-separated).
// Returns selected 0-based indices.
func (p *prompter) askMultiSelect(prompt string, options []string) []int {
	fmt.Fprintln(p.out, prompt)
	for i, opt := range options {
		fmt.Fprintf(p.out, "  [%d] %s\n", i+1, opt)
	}
	fmt.Fprintf(p.out, "  [a] All\n")
	for {
		answer := p.ask("Selection (comma-separated, or 'a' for all):")
		if strings.ToLower(answer) == "a" {
			indices := make([]int, len(options))
			for i := range options {
				indices[i] = i
			}
			return indices
		}
		parts := strings.Split(answer, ",")
		var indices []int
		valid := true
		for _, part := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 1 || n > len(options) {
				valid = false
				break
			}
			indices = append(indices, n-1)
		}
		if valid && len(indices) > 0 {
			return indices
		}
		fmt.Fprintf(p.out, "Enter numbers between 1 and %d, separated by commas.\n", len(options))
	}
}
