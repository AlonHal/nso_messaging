"""MCP server exposing a tool to extract text from local PDF files."""
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from pypdf import PdfReader

mcp = FastMCP("pdf-reader")

# Restrict reads to the workspace root to avoid arbitrary filesystem access.
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]


@mcp.tool()
def read_pdf(path: str, start_page: int = 1, end_page: int | None = None) -> str:
    """Extract text from a PDF file within the workspace.

    Args:
        path: Path to the PDF, absolute or relative to the workspace root.
        start_page: 1-based first page to extract (inclusive).
        end_page: 1-based last page to extract (inclusive). Defaults to the last page.
    """
    pdf_path = Path(path)
    if not pdf_path.is_absolute():
        pdf_path = WORKSPACE_ROOT / pdf_path
    pdf_path = pdf_path.resolve()

    if WORKSPACE_ROOT not in pdf_path.parents and pdf_path != WORKSPACE_ROOT:
        raise ValueError("Refusing to read files outside the workspace")
    if not pdf_path.is_file():
        raise FileNotFoundError(f"No such PDF file: {pdf_path}")

    reader = PdfReader(str(pdf_path))
    total_pages = len(reader.pages)
    last_page = end_page if end_page is not None else total_pages
    first_index = max(start_page, 1) - 1
    last_index = min(last_page, total_pages)

    chunks = []
    for i in range(first_index, last_index):
        chunks.append(f"--- Page {i + 1} ---\n{reader.pages[i].extract_text() or ''}")
    return "\n\n".join(chunks)


if __name__ == "__main__":
    mcp.run()
