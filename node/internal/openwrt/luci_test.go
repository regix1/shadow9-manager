package openwrt

import (
	"strings"
	"testing"
)

func TestProtocolPackageNoticeIsSilentWhenItIsInstalled(t *testing.T) {
	shell := newFakeShell()
	if notice := (Router{Shell: shell}).ProtocolPackageNotice("wg0"); notice != "" {
		t.Errorf("said something about an installed package: %s", notice)
	}
}

// The tunnel comes up either way, so this is a notice rather than a failure,
// but it has to say plainly what is missing and what LuCI will not show.
func TestProtocolPackageNoticeSaysWhatIsMissingAndHowToInstallIt(t *testing.T) {
	shell := newFakeShell()
	shell.installed = map[string]bool{}
	notice := (Router{Shell: shell}).ProtocolPackageNotice("wg0")
	for _, want := range []string{
		ProtocolPackage,
		"is not installed",
		"apk add",
		"opkg install",
		"service rpcd restart",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("the notice does not mention %q:\n%s", want, notice)
		}
	}
}

// A router where neither manager answers is unknown, not missing. Reporting
// "not installed" would send someone installing a package they already have.
func TestNeitherPackageManagerAnsweringIsReportedAsUnknown(t *testing.T) {
	shell := newFakeShell()
	shell.absent["apk"] = true
	shell.absent["opkg"] = true
	router := Router{Shell: shell}
	if state := router.InstalledState(ProtocolPackage); state != PackageUnknown {
		t.Errorf("state is %v, want PackageUnknown", state)
	}
	notice := router.ProtocolPackageNotice("wg0")
	if !strings.Contains(notice, "could not determine") {
		t.Errorf("the notice does not say it could not tell:\n%s", notice)
	}
	if strings.Contains(notice, "is not installed") {
		t.Errorf("an unknown state was reported as missing:\n%s", notice)
	}
}

func TestOnlyOnePackageManagerPresentStillAnswers(t *testing.T) {
	for _, manager := range []string{"apk", "opkg"} {
		t.Run(manager, func(t *testing.T) {
			shell := newFakeShell()
			for _, other := range []string{"apk", "opkg"} {
				if other != manager {
					shell.absent[other] = true
				}
			}
			router := Router{Shell: shell}
			if state := router.InstalledState(ProtocolPackage); state != PackageInstalled {
				t.Errorf("%s did not report the package as installed", manager)
			}
			shell.installed = map[string]bool{}
			if state := router.InstalledState(ProtocolPackage); state != PackageMissing {
				t.Errorf("%s did not report the package as missing", manager)
			}
		})
	}
}

func TestPolicyPackageIsCheckedBeforeAPolicyJoin(t *testing.T) {
	shell := newFakeShell()
	router := Router{Shell: shell}
	if err := router.RequirePolicyPackage(); err != nil {
		t.Fatalf("RequirePolicyPackage rejected an installed package: %v", err)
	}
	shell.installed[PolicyPackage] = false
	err := router.RequirePolicyPackage()
	if err == nil {
		t.Fatal("RequirePolicyPackage accepted a missing package")
	}
	for _, want := range []string{PolicyPackage, "apk add", "opkg install"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the missing-package error does not mention %q: %v", want, err)
		}
	}
}

func TestRequireNamesThePackageToInstall(t *testing.T) {
	shell := newFakeShell()
	shell.absent["wg"] = true
	router := Router{Shell: shell}
	err := router.Require("wg", "wireguard-tools")
	if err == nil {
		t.Fatal("Require passed with wg missing")
	}
	if !strings.Contains(err.Error(), "wireguard-tools") {
		t.Errorf("the error does not name the package: %v", err)
	}
	if err := router.Require("uci", "the base system"); err != nil {
		t.Errorf("Require failed for a command that is present: %v", err)
	}
}
