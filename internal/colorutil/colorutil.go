package colorutil

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	colorCritical = color.New(color.FgRed, color.Bold)
	colorHigh     = color.New(color.FgYellow, color.Bold)
	colorMedium   = color.New(color.FgYellow)
	colorLow      = color.New(color.FgGreen)
)

// ApplyNoColor disables color output
func ApplyNoColor() {
	color.NoColor = true
}

// ColorizeSeverity returns the severity string with appropriate color
func ColorizeSeverity(severity string) string {
	switch severity {
	case "critical":
		return colorCritical.Sprint(severity)
	case "high":
		return colorHigh.Sprint(severity)
	case "medium":
		return colorMedium.Sprint(severity)
	case "low":
		return colorLow.Sprint(severity)
	default:
		return severity
	}
}

// ColorizeRiskLevel returns the risk level string with appropriate color
func ColorizeRiskLevel(level string) string {
	switch level {
	case "CRITICAL":
		return colorCritical.Sprint(level)
	case "HIGH":
		return colorHigh.Sprint(level)
	case "MEDIUM":
		return colorMedium.Sprint(level)
	case "LOW":
		return colorLow.Sprint(level)
	default:
		return level
	}
}

// PrintRiskLevel prints a risk level label with color
func PrintRiskLevel(label string, count int) {
	switch label {
	case "CRITICAL":
		colorCritical.Printf("  %-10s %d\n", label+":", count)
	case "HIGH":
		colorHigh.Printf("  %-10s %d\n", label+":", count)
	case "MEDIUM":
		colorMedium.Printf("  %-10s %d\n", label+":", count)
	case "LOW":
		colorLow.Printf("  %-10s %d\n", label+":", count)
	default:
		fmt.Printf("  %-10s %d\n", label+":", count)
	}
}

// ColorizePackageRisk returns a colored package string based on risk score
func ColorizePackageRisk(pkgInfo string, riskScore int) string {
	switch {
	case riskScore >= 75:
		return colorCritical.Sprint(pkgInfo)
	case riskScore >= 50:
		return colorHigh.Sprint(pkgInfo)
	case riskScore >= 25:
		return colorMedium.Sprint(pkgInfo)
	default:
		return colorLow.Sprint(pkgInfo)
	}
}
