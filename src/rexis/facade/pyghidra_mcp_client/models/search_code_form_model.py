from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar, Union

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchCodeFormModel")


@_attrs_define
class SearchCodeFormModel:
    """
    Attributes:
        binary_name (str):
        query (str):
        limit (Union[Unset, int]):  Default: 10.
    """

    binary_name: str
    query: str
    limit: Union[Unset, int] = 10
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        binary_name = self.binary_name

        query = self.query

        limit = self.limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "binary_name": binary_name,
                "query": query,
            }
        )
        if limit is not UNSET:
            field_dict["limit"] = limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        binary_name = d.pop("binary_name")

        query = d.pop("query")

        limit = d.pop("limit", UNSET)

        search_code_form_model = cls(
            binary_name=binary_name,
            query=query,
            limit=limit,
        )

        search_code_form_model.additional_properties = d
        return search_code_form_model

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
