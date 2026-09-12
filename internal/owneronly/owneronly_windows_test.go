//go:build windows

package owneronly

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The negative case on Windows. The unix half can be made permissive with a
// Chmod; here it takes a second ACE, which is also the realistic shape of the
// thing being ruled out — a DACL that grants the owner and somebody else.
func TestIsOwnerOnlyRefusesADACLGrantingEveryone(t *testing.T) {
	path := writeTemp(t, "key")
	if err := Apply(path); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if private, _ := IsOwnerOnly(path); !private {
		t.Fatal("precondition: the file is not owner-only before the grant")
	}

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("world SID: %v", err)
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}

	entry := func(s *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(s),
			},
		}
	}

	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry(sid), entry(everyone)}, nil)
	if err != nil {
		t.Fatalf("dacl: %v", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	private, err := IsOwnerOnly(path)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if private {
		t.Error("a DACL granting Everyone was reported as owner-only")
	}
}

// A nil DACL is not an empty one: it grants everybody everything. Reporting it
// as owner-only because it contains no entry that names somebody else would be
// exactly backwards.
func TestIsOwnerOnlyRefusesANilDACL(t *testing.T) {
	path := writeTemp(t, "key")
	err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil)
	if err != nil {
		t.Skipf("cannot set a nil DACL here: %v", err)
	}
	if private, err := IsOwnerOnly(path); err == nil && private {
		t.Error("a nil DACL was reported as owner-only")
	}
}
