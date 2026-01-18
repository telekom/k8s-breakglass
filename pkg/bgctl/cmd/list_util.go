package cmd

import "fmt"

func paginate[T any](items []T, page, pageSize int, all bool) ([]T, string) {
	if all || pageSize <= 0 {
		return items, ""
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []T{}, fmt.Sprintf("Showing page %d of %d (%d total items)", page, maxPage(len(items), pageSize), len(items))
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end], fmt.Sprintf("Showing page %d of %d (%d total items)", page, maxPage(len(items), pageSize), len(items))
}

func maxPage(total, pageSize int) int {
	if pageSize <= 0 {
		return 1
	}
	pages := total / pageSize
	if total%pageSize != 0 {
		pages++
	}
	if pages == 0 {
		return 1
	}
	return pages
}
