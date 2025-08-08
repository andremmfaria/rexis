import typer


def ensure_exactly_one(label: str, **kwargs) -> str:
    """
    Ensure exactly one of the provided keyword args is not None/empty.
    Returns the selected key.
    """
    provided = [k for k, v in kwargs.items() if v not in (None, [], "")]
    if len(provided) == 0:
        raise typer.BadParameter(f"{label}: exactly one of {', '.join(kwargs.keys())} is required.")
    if len(provided) > 1:
        raise typer.BadParameter(f"{label}: options {', '.join(provided)} are mutually exclusive.")
    return provided[0]


def make_batches(total: int, batch_size: int) -> list[tuple[int, int]]:
    """
    Split range [0, total) into batches of size batch_size.
    Last batch contains the remainder (does not need to divide evenly).
    Returns list of (start, end) indices, end-exclusive.
    """
    if total <= 0:
        raise typer.BadParameter("fetch_limit must be > 0")
    if batch_size <= 0:
        raise typer.BadParameter("batch must be > 0")

    batches = []
    start = 0
    while start < total:
        end = min(start + batch_size, total)
        batches.append((start, end))
        start = end
    return batches
