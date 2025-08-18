from typing import List, Optional, TypedDict


class FunctionInfo(TypedDict):
    name: str
    entry: str
    size: int
    is_thunk: bool
    calling_convention: Optional[str]


class DecompiledFunction(TypedDict, total=False):
    name: str
    entry: str
    c: str
    error: str


class ProgramInfo(TypedDict):
    name: str
    format: str
    language: str
    compiler: str
    image_base: str
    size: int
    sha256: str


class Features(TypedDict):
    program: ProgramInfo
    functions: List[FunctionInfo]
    imports: List[str]
    decompiled: List[DecompiledFunction]
