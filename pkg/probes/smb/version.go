// Package smb provides SMB-based probe functionality for Windows OS detection.
package smb

// windowsBuildMap maps Windows build numbers to friendly OS version names.
// This mapping covers major Windows releases from Windows 7 to Windows 11.
// Build numbers are extracted from the NTLMSSP challenge during SMB negotiation.
var windowsBuildMap = map[uint16]string{
	// Windows 7 / Server 2008 R2
	7600: "Windows 7 / Server 2008 R2",
	7601: "Windows 7 SP1 / Server 2008 R2 SP1",

	// Windows 8 / Server 2012
	9200: "Windows 8 / Server 2012",

	// Windows 8.1 / Server 2012 R2
	9600: "Windows 8.1 / Server 2012 R2",

	// Windows 10 builds
	10240: "Windows 10 1507",
	10586: "Windows 10 1511",
	14393: "Windows 10 1607 / Server 2016",
	15063: "Windows 10 1703",
	16299: "Windows 10 1709",
	17134: "Windows 10 1803",
	17763: "Windows 10 1809 / Server 2019",
	18362: "Windows 10 1903",
	18363: "Windows 10 1909",
	19041: "Windows 10 2004",
	19042: "Windows 10 20H2",
	19043: "Windows 10 21H1",
	19044: "Windows 10 21H2",
	19045: "Windows 10 22H2",

	// Windows 11 builds
	22000: "Windows 11 21H2",
	22621: "Windows 11 22H2",
	22631: "Windows 11 23H2",
	26100: "Windows 11 24H2",

	// Windows Server builds
	20348: "Windows Server 2022",
	25398: "Windows Server 2025",
}

// buildRanges maps build number ranges to versions for approximate matching.
// Used when exact build is not in the map.
type buildRange struct {
	MinBuild uint16
	MaxBuild uint16
	Version  string
}

var buildRanges = []buildRange{
	{7600, 7601, "Windows 7 / Server 2008 R2"},
	{9200, 9200, "Windows 8 / Server 2012"},
	{9600, 9600, "Windows 8.1 / Server 2012 R2"},
	{10240, 10586, "Windows 10 (Early)"},
	{14393, 14393, "Windows 10 1607 / Server 2016"},
	{15063, 16299, "Windows 10 (2017)"},
	{17134, 17763, "Windows 10 1803-1809 / Server 2019"},
	{18362, 18363, "Windows 10 1903/1909"},
	{19041, 19045, "Windows 10 2004-22H2"},
	{20348, 20348, "Windows Server 2022"},
	{22000, 22000, "Windows 11 21H2"},
	{22621, 22631, "Windows 11 22H2/23H2"},
	{25398, 25398, "Windows Server 2025"},
	{26100, 26100, "Windows 11 24H2"},
}

// GetWindowsVersion returns the friendly Windows version name for a build number.
// Returns empty string if the build number is not recognized.
func GetWindowsVersion(buildNumber uint16) string {
	// First try exact match
	if version, ok := windowsBuildMap[buildNumber]; ok {
		return version
	}

	// Fall back to range matching for unknown exact builds
	for _, r := range buildRanges {
		if buildNumber >= r.MinBuild && buildNumber <= r.MaxBuild {
			return r.Version
		}
	}

	// Approximate based on known boundaries
	switch {
	case buildNumber < 7600:
		return "Windows Vista or earlier"
	case buildNumber >= 7600 && buildNumber < 9200:
		return "Windows 7 / Server 2008 R2"
	case buildNumber >= 9200 && buildNumber < 9600:
		return "Windows 8 / Server 2012"
	case buildNumber >= 9600 && buildNumber < 10240:
		return "Windows 8.1 / Server 2012 R2"
	case buildNumber >= 10240 && buildNumber < 22000:
		return "Windows 10 / Server 2016-2022"
	case buildNumber >= 22000:
		return "Windows 11 / Server 2022+"
	}

	return ""
}

// GetBuildNumber extracts the build number from the NTLMSSP version field.
// The version is packed as: [Major (1)][Minor (1)][Build (2)][Reserved (3)][Revision (1)]
func GetBuildNumber(versionBytes []byte) uint16 {
	if len(versionBytes) < 4 {
		return 0
	}
	return uint16(versionBytes[2]) | uint16(versionBytes[3])<<8
}

// GetMajorMinor extracts major and minor version from NTLMSSP version field.
func GetMajorMinor(versionBytes []byte) (major, minor byte) {
	if len(versionBytes) < 2 {
		return 0, 0
	}
	return versionBytes[0], versionBytes[1]
}

// IsWindowsBuild returns true if the build number appears to be a valid Windows build.
func IsWindowsBuild(buildNumber uint16) bool {
	// Windows builds are typically in the range 2600+ (Windows XP onwards)
	return buildNumber >= 2600
}
