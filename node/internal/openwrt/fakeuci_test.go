package openwrt

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The research this package was written from had no OpenWrt device, so the
// tests drive a fake uci instead. It models what uci does to /etc/config,
// including the parts that matter here: add_list appends, deleting a section
// by type index shifts the remaining ones down, and nothing reaches the file
// until commit.

type fakeSection struct {
	name    string // empty for an anonymous section
	kind    string
	order   []string
	options map[string][]string
	isList  map[string]bool
}

func (s *fakeSection) clone() *fakeSection {
	c := &fakeSection{
		name:    s.name,
		kind:    s.kind,
		order:   append([]string(nil), s.order...),
		options: make(map[string][]string, len(s.options)),
		isList:  make(map[string]bool, len(s.isList)),
	}
	for k, v := range s.options {
		c.options[k] = append([]string(nil), v...)
	}
	for k, v := range s.isList {
		c.isList[k] = v
	}
	return c
}

type fakePackage struct {
	sections []*fakeSection
}

func (p *fakePackage) clone() *fakePackage {
	c := &fakePackage{}
	for _, s := range p.sections {
		c.sections = append(c.sections, s.clone())
	}
	return c
}

func (p *fakePackage) named(name string) *fakeSection {
	for _, s := range p.sections {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (p *fakePackage) remove(s *fakeSection) {
	for i, candidate := range p.sections {
		if candidate == s {
			p.sections = append(p.sections[:i], p.sections[i+1:]...)
			return
		}
	}
}

// fakeShell answers uci and the init scripts. Everything the client does to
// the router goes through Shell, so a test drives the whole write path.
type fakeShell struct {
	working   map[string]*fakePackage
	committed map[string]*fakePackage
	absent    map[string]bool   // commands not on PATH
	failing   map[string]string // "uci set network.wg0.mtu" and the like
	failures  map[string]int
	output    map[string]string
	calls     []string
	stdin     []Stdin
	deadlines []time.Duration
	reloaded  []string
	stopped   []string
	missing   map[string]bool
	installed map[string]bool
	// pbrStale is set by every commit the pbr service would have to read, and
	// cleared by a reload. pbrSettleQueries is how many route queries still
	// answer "no such table" after that reload, because the live service
	// builds its table asynchronously; pbrSettle counts those down. Together
	// they mean a client that never reloads, or that checks once straight
	// afterwards, sees nothing.
	pbrStale         bool
	pbrSettleQueries int
	pbrSettle        int
	noManager        bool
	snapshots        map[string]*fakePackage
	nextSave         int
}

func newFakeShell(existing ...string) *fakeShell {
	f := &fakeShell{
		working:   map[string]*fakePackage{},
		committed: map[string]*fakePackage{},
		absent:    map[string]bool{},
		failing:   map[string]string{},
		failures:  map[string]int{},
		output:    map[string]string{},
		missing:   map[string]bool{},
		installed: map[string]bool{ProtocolPackage: true, PolicyPackage: true},
		snapshots: map[string]*fakePackage{},
	}
	for _, pkg := range append([]string{"network", "firewall", "system"}, existing...) {
		f.working[pkg] = &fakePackage{}
		f.committed[pkg] = &fakePackage{}
	}
	return f
}

var anonymousKey = regexp.MustCompile(`^@([A-Za-z0-9_]+)\[(-?\d+)\]$`)

// resolve splits "network.wg0.proto" into its package, section and option.
func (f *fakeShell) resolve(key string, create bool) (*fakePackage, *fakeSection, string, error) {
	parts := strings.SplitN(key, ".", 3)
	if len(parts) < 2 {
		return nil, nil, "", fmt.Errorf("uci: Invalid argument")
	}
	pkg, ok := f.working[parts[0]]
	if !ok {
		return nil, nil, "", fmt.Errorf("uci: Entry not found")
	}
	option := ""
	if len(parts) == 3 {
		option = parts[2]
	}
	if match := anonymousKey.FindStringSubmatch(parts[1]); match != nil {
		index, _ := strconv.Atoi(match[2])
		var of []*fakeSection
		for _, s := range pkg.sections {
			if s.kind == match[1] {
				of = append(of, s)
			}
		}
		if index < 0 {
			index += len(of)
		}
		if index < 0 || index >= len(of) {
			return pkg, nil, option, fmt.Errorf("uci: Entry not found")
		}
		return pkg, of[index], option, nil
	}
	section := pkg.named(parts[1])
	if section == nil {
		if !create {
			return pkg, nil, option, fmt.Errorf("uci: Entry not found")
		}
		section = &fakeSection{
			name:    parts[1],
			options: map[string][]string{},
			isList:  map[string]bool{},
		}
		pkg.sections = append(pkg.sections, section)
	}
	return pkg, section, option, nil
}

func (f *fakeShell) Look(name string) error {
	if f.absent[name] {
		return fmt.Errorf("%s: not found", name)
	}
	return nil
}

func (f *fakeShell) Run(ctx context.Context, stdin Stdin, name string, args ...string) ([]byte, error) {
	call := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, call)
	f.stdin = append(f.stdin, stdin)
	deadline, set := ctx.Deadline()
	if !set {
		f.deadlines = append(f.deadlines, 0)
	} else {
		f.deadlines = append(f.deadlines, time.Until(deadline))
	}
	if f.absent[name] {
		return nil, fmt.Errorf("%s: not found", name)
	}
	// A service that exits nonzero has still read the new configuration; pbr
	// reports a diagnostic status for things like a missing ipset while its
	// routes are in place. Recording the effect before the injected failure is
	// what lets a test tell those two apart.
	f.serviceAction(name, args)
	for prefix, remaining := range f.failures {
		if remaining > 0 && strings.HasPrefix(call, prefix) {
			f.failures[prefix] = remaining - 1
			return []byte("uci: I/O error"), fmt.Errorf("exit status 1")
		}
	}
	for prefix, message := range f.failing {
		if strings.HasPrefix(call, prefix) {
			return []byte(message), fmt.Errorf("exit status 1")
		}
	}
	if output, ok := f.output[call]; ok {
		return []byte(output), nil
	}
	switch name {
	case "uci":
		if len(args) == 1 && args[0] == "batch" {
			return f.batch(stdin)
		}
		if len(args) == 2 && args[0] == "export" {
			pkg, ok := f.working[args[1]]
			if !ok {
				return nil, fmt.Errorf("uci: Entry not found")
			}
			f.nextSave++
			id := fmt.Sprintf("fake-snapshot-%d", f.nextSave)
			f.snapshots[id] = pkg.clone()
			return []byte(id), nil
		}
		if len(args) == 2 && args[0] == "import" {
			pkg, ok := f.snapshots[string(stdin)]
			if !ok {
				return nil, fmt.Errorf("uci: Invalid argument")
			}
			f.working[args[1]] = pkg.clone()
			f.committed[args[1]] = pkg.clone()
			return nil, nil
		}
		return f.uci(args)
	case "touch":
		// uci addresses a package only once its file exists, which is why the
		// client touches it before writing settings.
		for _, path := range args {
			pkg, isConfig := strings.CutPrefix(path, "/etc/config/")
			if !isConfig {
				continue
			}
			if _, exists := f.working[pkg]; !exists {
				f.working[pkg] = &fakePackage{}
				f.committed[pkg] = &fakePackage{}
			}
		}
		return nil, nil
	case "rm":
		return nil, nil
	case "test":
		if len(args) == 2 && args[0] == "-f" && f.missing[args[1]] {
			return nil, fmt.Errorf("exit status 1")
		}
		return nil, nil
	case "/bin/sh":
		if len(args) == 3 && args[0] == "/etc/rc.common" {
			return nil, nil
		}
	case "apk", "opkg":
		if f.noManager {
			return nil, fmt.Errorf("exit status 127")
		}
		wanted := args[len(args)-1]
		if f.installed[wanted] {
			return []byte(wanted + "\n"), nil
		}
		return nil, fmt.Errorf("exit status 1")
	case "ip":
		if len(args) == 5 && (args[0] == "-4" || args[0] == "-6") &&
			args[1] == "route" && args[2] == "show" && args[3] == "table" &&
			strings.HasPrefix(args[4], "pbr_") {
			iface := strings.TrimPrefix(args[4], "pbr_")
			if f.hasPBRTable(iface) {
				return []byte("default dev " + iface + " scope link\n"), nil
			}
			return nil, fmt.Errorf("FIB table does not exist")
		}
		if len(args) == 3 && (args[0] == "-4" || args[0] == "-6") &&
			args[1] == "rule" && args[2] == "show" {
			if network := f.committed["network"]; network != nil {
				for _, section := range network.sections {
					if section.name != "" && f.hasPBRTable(section.name) {
						return []byte("29998: from all fwmark 0x20000/0xff0000 lookup pbr_" +
							section.name + "\n"), nil
					}
				}
			}
			return nil, nil
		}
	case "ifstatus":
		return []byte(`{"up":true,"pending":false}`), nil
	}
	if strings.HasPrefix(name, "/etc/init.d/") && len(args) == 1 {
		switch args[0] {
		case "reload", "stop", "disable":
			return nil, nil
		}
	}
	return nil, fmt.Errorf("%s: not found", name)
}

// serviceAction records what an init script call did to the live state the
// router later reads back through ip and ifstatus.
func (f *fakeShell) serviceAction(name string, args []string) {
	service, isService := strings.CutPrefix(name, "/etc/init.d/")
	if !isService || len(args) != 1 {
		return
	}
	switch args[0] {
	case "reload":
		f.reloaded = append(f.reloaded, service)
		if service == "pbr" {
			f.pbrStale = false
			f.pbrSettle = f.pbrSettleQueries
		}
	case "stop":
		f.stopped = append(f.stopped, service)
		if service == "pbr" {
			f.pbrStale = true
		}
	}
}

func (f *fakeShell) hasPBRTable(iface string) bool {
	if f.pbrStale {
		return false
	}
	if f.pbrSettle > 0 {
		f.pbrSettle--
		return false
	}
	network := f.committed["network"]
	if network == nil || network.named(iface) == nil {
		return false
	}
	pbr := f.committed["pbr"]
	if pbr == nil {
		return false
	}
	config := pbr.named("config")
	if config == nil || !uciEnabled(strings.Join(config.options["enabled"], " ")) {
		return false
	}
	return hasListValue(strings.Join(config.options["supported_interface"], " "), iface)
}

func (f *fakeShell) batch(stdin Stdin) ([]byte, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(stdin)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		argument := fields[1]
		key, value, found := strings.Cut(argument, "=")
		if !found {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		value = strings.Trim(value, "'")
		if _, err := f.uci([]string{fields[0], key + "=" + value}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (f *fakeShell) uci(args []string) ([]byte, error) {
	quiet := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		quiet = quiet || args[0] == "-q"
		args = args[1:]
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("uci: Invalid argument")
	}
	action, rest := args[0], args[1:]
	switch action {
	case "set", "add_list":
		if len(rest) != 1 {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		key, value, found := strings.Cut(rest[0], "=")
		if !found {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		_, section, option, err := f.resolve(key, true)
		if err != nil {
			return nil, err
		}
		if option == "" {
			section.kind = value
			return nil, nil
		}
		if _, seen := section.options[option]; !seen {
			section.order = append(section.order, option)
		}
		if action == "add_list" {
			section.isList[option] = true
			section.options[option] = append(section.options[option], value)
		} else {
			section.options[option] = []string{value}
		}
		return nil, nil
	case "delete":
		if len(rest) != 1 {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		pkg, section, option, err := f.resolve(rest[0], false)
		if err != nil {
			return nil, err
		}
		if option != "" {
			if _, seen := section.options[option]; !seen {
				return nil, fmt.Errorf("uci: Entry not found")
			}
			delete(section.options, option)
			delete(section.isList, option)
			for index, name := range section.order {
				if name == option {
					section.order = append(section.order[:index], section.order[index+1:]...)
					break
				}
			}
			return nil, nil
		}
		pkg.remove(section)
		return nil, nil
	case "get":
		_, section, option, err := f.resolve(rest[0], false)
		if err != nil {
			return nil, err
		}
		values, seen := section.options[option]
		if !seen {
			if option == "" {
				return []byte(section.kind + "\n"), nil
			}
			return nil, fmt.Errorf("uci: Entry not found")
		}
		return []byte(strings.Join(values, " ") + "\n"), nil
	case "changes":
		if len(rest) != 1 {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		working, workingOK := f.working[rest[0]]
		committed, committedOK := f.committed[rest[0]]
		if !workingOK || !committedOK {
			return nil, fmt.Errorf("uci: Entry not found")
		}
		if !reflect.DeepEqual(working, committed) {
			return []byte(rest[0] + ".changed='1'\n"), nil
		}
		return nil, nil
	case "commit":
		if len(rest) != 1 {
			return nil, fmt.Errorf("uci: Invalid argument")
		}
		pkg, ok := f.working[rest[0]]
		if !ok {
			return nil, fmt.Errorf("uci: Entry not found")
		}
		f.committed[rest[0]] = pkg.clone()
		// The pbr service reads both of these and cannot see a change until
		// it is reloaded, and a network reload takes the interface down and
		// up under it.
		if rest[0] == "pbr" || rest[0] == "network" {
			f.pbrStale = true
		}
		return nil, nil
	case "revert":
		pkg, ok := f.committed[rest[0]]
		if !ok {
			return nil, fmt.Errorf("uci: Entry not found")
		}
		f.working[rest[0]] = pkg.clone()
		return nil, nil
	}
	_ = quiet
	return nil, fmt.Errorf("uci: Invalid argument")
}

// render prints a committed package the way /etc/config/<name> looks on disk.
func (f *fakeShell) render(pkg string) string {
	p, ok := f.committed[pkg]
	if !ok {
		return ""
	}
	var b strings.Builder
	for i, section := range p.sections {
		if i > 0 {
			b.WriteString("\n")
		}
		if section.name == "" {
			fmt.Fprintf(&b, "config %s\n", section.kind)
		} else {
			fmt.Fprintf(&b, "config %s '%s'\n", section.kind, section.name)
		}
		for _, option := range section.order {
			values, seen := section.options[option]
			if !seen {
				continue
			}
			kind := "option"
			if section.isList[option] {
				kind = "list"
			}
			for _, value := range values {
				fmt.Fprintf(&b, "\t%s %s '%s'\n", kind, option, value)
			}
		}
	}
	return b.String()
}

// addSection puts an existing section into a package, for tests that start
// from a router that already has a LAN zone.
func (f *fakeShell) addSection(pkg, name, kind string, options map[string][]string) {
	target, ok := f.working[pkg]
	if !ok {
		target = &fakePackage{}
		f.working[pkg] = target
		f.committed[pkg] = &fakePackage{}
	}
	section := &fakeSection{name: name, kind: kind, options: map[string][]string{}, isList: map[string]bool{}}
	keys := make([]string, 0, len(options))
	for k := range options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		section.order = append(section.order, k)
		section.options[k] = append([]string(nil), options[k]...)
		section.isList[k] = len(options[k]) > 1
	}
	target.sections = append(target.sections, section)
	f.committed[pkg] = target.clone()
}
