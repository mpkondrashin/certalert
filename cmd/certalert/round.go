package main

import (
	"fmt"
	"math"
)

const unit = 1024

var suffix = []string{
	"KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB",
}

func formatFileSize(fileSize int64) string {
	if fileSize < unit {
		return fmt.Sprintf("%d B", fileSize)
	}

	div, exp := int64(unit), 0
	for n := fileSize / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	fileSizeFloat := float64(fileSize) / float64(div)
	fileSizeRounded := math.Round(fileSizeFloat*100) / 100
	return fmt.Sprintf("%.2f %s", fileSizeRounded, suffix[exp])
}
