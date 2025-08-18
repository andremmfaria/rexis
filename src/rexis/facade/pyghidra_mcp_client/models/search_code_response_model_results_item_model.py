from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchCodeResponseModelResultsItemModel")


@_attrs_define
class SearchCodeResponseModelResultsItemModel:
    """
    Attributes:
        function_name (str): The name of the function where the code was found.
        code (str): The code snippet that matched the search query.
        similarity (float): The similarity score of the search result.
    """

    function_name: str
    code: str
    similarity: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        function_name = self.function_name

        code = self.code

        similarity = self.similarity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "function_name": function_name,
                "code": code,
                "similarity": similarity,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        function_name = d.pop("function_name")

        code = d.pop("code")

        similarity = d.pop("similarity")

        search_code_response_model_results_item_model = cls(
            function_name=function_name,
            code=code,
            similarity=similarity,
        )

        search_code_response_model_results_item_model.additional_properties = d
        return search_code_response_model_results_item_model

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
