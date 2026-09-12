//go:build windows

package owneronly

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// currentUserSID returns the SID of the account this process runs as.
func currentUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("reading the process token: %w", err)
	}
	return user.User.Sid, nil
}

func Apply(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}

	// One entry: this user, full control, not inherited by anything since a file
	// has no children.
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("building the DACL for %s: %w", path, err)
	}

	// PROTECTED is the load-bearing flag. Without it the DACL set here is merged
	// with the entries inherited from the parent directory -- which under a
	// user's profile typically grant Administrators and SYSTEM, and under a
	// temp or shared directory can grant considerably more. Protecting it drops
	// the inherited entries instead of adding to them, which is what makes this
	// "only the owner" rather than "the owner, plus whoever the parent said".
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("restricting %s to its owner: %w", path, err)
	}
	return nil
}

func IsOwnerOnly(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, fmt.Errorf("reading the security descriptor of %s: %w", path, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return false, fmt.Errorf("reading the DACL of %s: %w", path, err)
	}
	// A nil DACL is not an empty one: it grants everyone everything.
	if dacl == nil {
		return false, nil
	}

	sid, err := currentUserSID()
	if err != nil {
		return false, err
	}

	// Every entry must name this user. One that does not is somebody else with
	// access, which is the thing being ruled out.
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, fmt.Errorf("reading ACE %d of %s: %w", i, path, err)
		}
		if !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return false, nil
		}
	}
	return dacl.AceCount > 0, nil
}
