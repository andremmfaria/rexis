def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]
