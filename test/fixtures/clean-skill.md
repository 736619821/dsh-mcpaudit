# Benign Skill: PDF Tools

This MCP server provides PDF tools for the agent:

## Tools

### read_pdf
Reads the content of a PDF file and returns it as text.

Arguments:
- `file_path`: path to the PDF file (must be .pdf)

### merge_pdf
Merges multiple PDF files into a single document.

Arguments:
- `files`: array of PDF file paths

## Usage Notes

- Files larger than 100MB are rejected
- All operations are local, no data leaves the machine
- Errors are reported with clear messages

## Example

```
read_pdf: docs/report.pdf
merge_pdf: [a.pdf, b.pdf]
```
