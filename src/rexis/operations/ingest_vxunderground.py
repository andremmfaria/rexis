import json
import re
import time
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import pymupdf
import requests
from bs4 import BeautifulSoup
from haystack import Document
from rexis.facade.haystack import index_documents
from rexis.utils.config import config
from rexis.utils.utils import LOGGER


def ingest_vxunderground_exec(
    type: str,
    year: Optional[int] = None,
    papers: bool = False,
    path: Optional[str] = None,
    download_dir: Path = Path(config.ingestion.vxu.default_download_dir),
    batch: int = 50,
    base_url: str = config.ingestion.vxu.default_base_url,
) -> None:
    download_dir = Path(download_dir)
    download_dir.mkdir(parents=True, exist_ok=True)

    if type == "apt":
        if year is None:
            raise ValueError("type='apt' requires year.")
        if not papers:
            raise ValueError("type='apt' requires --papers.")

        LOGGER.info("[VXU] Ingest APT | year=%d | papers=%s", year, papers)
        _ingest_apt_papers(year=year, base_url=base_url, download_dir=download_dir, batch=batch)

    elif type == "paper":
        if not path:
            raise ValueError("type='paper' requires --path")
        LOGGER.info("[VXU] Ingest papers from path: %s", path)
        _ingest_papers_from_path(
            path=path, base_url=base_url, download_dir=download_dir, batch=batch
        )

    else:
        raise ValueError(f"Unknown type: {type}")


def _ingest_apt_papers(year: int, base_url: str, download_dir: Path, batch: int) -> None:
    candidates = [
        f"/APT/{year}/",
        f"/{year}/APT/",
        f"/APT/{year}/Papers/",
    ]

    pdf_urls = set()
    for rel in candidates:
        url = urljoin(base_url, rel)
        LOGGER.info("Discovering PDFs at: %s", url)
        try:
            pdfs_here = _discover_pdfs(url)
            pdf_urls.update(pdfs_here)
            LOGGER.info("Found %d PDFs at %s", len(pdfs_here), url)
        except Exception as e:
            LOGGER.warning("Discovery failed at %s: %s", url, e)

        time.sleep(config.ingestion.vxu.rate_delay_sec)

    if not pdf_urls:
        LOGGER.warning("No PDFs found for APT year %d.", year)
        return

    _download_extract_index_pdfs(
        pdf_urls=sorted(pdf_urls),
        base_url=base_url,
        download_dir=download_dir / f"APT_{year}" / "papers",
        batch=batch,
    )



def _ingest_papers_from_path(path: str, base_url: str, download_dir: Path, batch: int) -> None:
    roots = ["/Papers/", "/APT/", "/"]
    pdf_urls = set()

    for root in roots:
        url = urljoin(
            base_url,
            urljoin(root.lstrip("/"), path.lstrip("/")) + ("" if path.endswith("/") else "/"),
        )
        LOGGER.info("Discovering PDFs at: %s", url)
        try:
            pdfs_here = _discover_pdfs(url)
            pdf_urls.update(pdfs_here)
            LOGGER.info("Found %d PDFs at %s", len(pdfs_here), url)
        except Exception as e:
            LOGGER.debug("Path discovery miss at %s: %s", url, e)
        time.sleep(config.ingestion.vxu.rate_delay_sec)

    if not pdf_urls:
        LOGGER.warning("No PDFs found under path: %s", path)
        return

    _download_extract_index_pdfs(
        pdf_urls=sorted(pdf_urls),
        base_url=base_url,
        download_dir=download_dir / "path_ingest" / _safe_fs_name(path),
        batch=batch,
    )


def _download_extract_index_pdfs(
    pdf_urls: List[str], base_url: str, download_dir: Path, batch: int
) -> None:
    download_dir.mkdir(parents=True, exist_ok=True)
    batch_docs: List[Document] = []

    for i, pdf_url in enumerate(pdf_urls, 1):
        try:
            local_pdf = _download_file(pdf_url, download_dir)
            text = _pdf_to_text(local_pdf)
            if not text.strip():
                LOGGER.warning("Empty text extracted from %s", local_pdf)
                continue

            # Wrap as JSON string (to match your indexer expectations)
            payload = {
                "source": "vx-underground",
                "url": pdf_url,
                "local_path": str(local_pdf),
                "title": local_pdf.stem,
                "extracted_text": text,
            }
            doc = Document(
                id=f"vxu::{_stable_doc_id(pdf_url)}",
                content=json.dumps(payload),
                meta={"source": "vx-underground", "url": pdf_url, "filename": local_pdf.name},
            )
            batch_docs.append(doc)

            LOGGER.debug("Prepared doc %d/%d (%s)", i, len(pdf_urls), local_pdf.name)

            if len(batch_docs) >= batch:
                LOGGER.info("Indexing batch of %d VXU paper documents...", len(batch_docs))
                index_documents(batch_docs, refresh=True)
                batch_docs = []

        except Exception as e:
            LOGGER.warning("Failed to process PDF %s: %s", pdf_url, e)

        time.sleep(config.ingestion.vxu.rate_delay_sec)

    if batch_docs:
        LOGGER.info("Indexing final batch of %d VXU paper documents...", len(batch_docs))
        index_documents(batch_docs, refresh=True)


def _discover_pdfs(index_url: str) -> List[str]:
    links = _discover_links(index_url)
    return [u for u in links if u.lower().endswith(".pdf")]


def _discover_links(index_url: str) -> List[str]:
    r = _http_get(index_url)
    soup = BeautifulSoup(r.text, "html.parser")
    seen = set()

    for a in soup.find_all("a", href=True):
        href = a["href"]
        url = urljoin(index_url, href)
        if _same_host(index_url, url):
            seen.add(url)

    return sorted(seen)


def _download_file(url: str, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = _filename_from_url(url)
    out = dest_dir / filename

    LOGGER.info("Downloading: %s -> %s", url, out)
    with requests.get(
        url,
        headers={"User-Agent": config.ingestion.vxu.user_agent},
        stream=True,
        timeout=config.ingestion.vxu.req_timeout,
    ) as r:
        r.raise_for_status()
        with open(out, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    return out


def _pdf_to_text(path: Path) -> str:
    text_parts: List[str] = []
    with pymupdf.open(path) as doc:
        for page in doc:
            text_parts.append(page.get_text("text"))
    text = "\n".join(text_parts)
    return _normalize_whitespace(text)


def _normalize_whitespace(s: str) -> str:
    s = s.replace("\r", "")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _http_get(url: str) -> requests.Response:
    LOGGER.debug("GET %s", url)
    r = requests.get(
        url,
        headers={"User-Agent": config.ingestion.vxu.user_agent},
        timeout=config.ingestion.vxu.req_timeout,
    )
    r.raise_for_status()
    return r


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


def _filename_from_url(url: str) -> str:
    name = Path(urlparse(url).path).name or "download"
    return name or "download"


def _stable_doc_id(url: str) -> str:
    """
    Create a deterministic, FS-safe id from a URL path.
    """
    path = urlparse(url).path
    safe = re.sub(r"[^A-Za-z0-9._/-]+", "_", path).strip("/")
    return safe.replace("/", "::")


def _safe_fs_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")
