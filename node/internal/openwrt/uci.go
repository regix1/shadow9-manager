// Package openwrt writes the router's UCI configuration and reloads the
// services that read it. Everything that touches the router goes through
// Shell, so tests drive the whole path with a fake uci.
package openwrt

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Stdin is text supplied to a command without putting it in the process list.
type Stdin string

// Shell runs one command on the router and returns its combined output.
type Shell interface {
	Run(ctx context.Context, stdin Stdin, name string, args ...string) ([]byte, error)
	Look(name string) error
}

// SystemShell runs commands through os/exec. It is the only place in this
// package that reaches the real router.
type SystemShell struct{}

// Run executes name with args and returns stdout and stderr together.
func (SystemShell) Run(ctx context.Context, stdin Stdin, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(string(stdin))
	return command.CombinedOutput()
}

// Look reports whether name is on PATH.
func (SystemShell) Look(name string) error {
	_, err := exec.LookPath(name)
	return err
}

const (
	uciTimeout     = 10 * time.Second
	fileTimeout    = 10 * time.Second
	packageTimeout = 30 * time.Second
	reloadTimeout  = 2 * time.Minute
)

// Command is one uci invocation, without the leading "uci".
type Command struct {
	Args  []string
	Stdin Stdin
	// Optional marks a command whose failure is expected and carries no
	// meaning, which is what deleting a section that was never created does.
	Optional bool
}

// String renders the command the way it would be typed, for error messages
// and for tests. Secret values are supplied through Stdin and never appear here.
func (c Command) String() string {
	return "uci " + strings.Join(c.Args, " ")
}

func set(key, value string) Command {
	return Command{Args: []string{"set", key + "=" + value}}
}

func setSecret(key, value string) Command {
	return Command{
		Args:  []string{"batch"},
		Stdin: Stdin("set " + key + "='" + value + "'\n"),
	}
}

func addList(key, value string) Command {
	return Command{Args: []string{"add_list", key + "=" + value}}
}

func remove(key string) Command {
	return Command{Args: []string{"-q", "delete", key}, Optional: true}
}

// Router applies UCI configuration through a Shell.
type Router struct {
	Shell        Shell
	checkTimeout time.Duration
}

func (r Router) run(timeout time.Duration, stdin Stdin, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return r.Shell.Run(ctx, stdin, name, args...)
}

// Get reads a single UCI value. A missing value is an empty string, which is
// what "uci -q get" already does, so a caller checks for "" rather than an
// error it cannot act on.
func (r Router) Get(key string) string {
	out, err := r.run(uciTimeout, "", "uci", "-q", "get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Apply runs commands in order and stops at the first one that fails, unless
// the command was marked Optional.
func (r Router) Apply(commands []Command) error {
	for _, c := range commands {
		out, err := r.run(uciTimeout, c.Stdin, "uci", c.Args...)
		if err != nil && !c.Optional {
			if c.Stdin != "" {
				return fmt.Errorf("%s: %w", c, err)
			}
			return fmt.Errorf("%s: %w: %s", c, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

// Commit writes the staged changes for one UCI package to disk.
func (r Router) Commit(pkg string) error {
	return r.Apply([]Command{{Args: []string{"commit", pkg}}})
}

// Reload restarts the service that reads a UCI package. Reload rather than
// restart, so interfaces this client did not create stay up.
func (r Router) Reload(service string) error {
	script := "/etc/init.d/" + service
	out, err := r.run(reloadTimeout, "", script, "reload")
	if err != nil {
		return fmt.Errorf("%s reload: %w: %s", script, err, bytes.TrimSpace(out))
	}
	return nil
}

// Require checks that a command the client depends on is present, and says
// what to install when it is not.
func (r Router) Require(name, packageName string) error {
	if err := r.Shell.Look(name); err != nil {
		return fmt.Errorf("%s was not found on PATH, install %s first", name, packageName)
	}
	return nil
}

// ClearPeers deletes every peer section on an interface, whether this client
// wrote it or a previous version did. add_list appends, so a second join
// would otherwise leave the old peer in place next to the new one and
// accumulate duplicate allowed_ips.
//
// uci addresses sections of a type by index, and the index shifts down as
// each one goes, so this always deletes index zero until uci reports there is
// nothing left. The bound stops a uci that never reports failure from
// spinning forever.
func (r Router) ClearPeers(iface string) {
	const mostPeersWorthClearing = 64
	key := fmt.Sprintf("network.@%s[0]", PeerSectionType(iface))
	for i := 0; i < mostPeersWorthClearing; i++ {
		if _, err := r.run(uciTimeout, "", "uci", "-q", "delete", key); err != nil {
			return
		}
	}
}

// PeerSectionType is the UCI section type netifd looks up peers by. It must
// be exactly "wireguard_" followed by the interface name.
func PeerSectionType(iface string) string {
	return "wireguard_" + iface
}
