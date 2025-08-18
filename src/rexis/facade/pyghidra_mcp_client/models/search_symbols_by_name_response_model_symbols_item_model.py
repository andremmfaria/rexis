from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SearchSymbolsByNameResponseModelSymbolsItemModel")


@_attrs_define
class SearchSymbolsByNameResponseModelSymbolsItemModel:
    """
    Attributes:
        name (str): The name of the symbol.
        address (str): The address of the symbol.
        type_ (str): The type of the symbol.
        namespace (str): The namespace of the symbol.
        source (str): The source of the symbol.
        refcount (int): The reference count of the symbol.
    """

    name: str
    address: str
    type_: str
    namespace: str
    source: str
    refcount: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        address = self.address

        type_ = self.type_

        namespace = self.namespace

        source = self.source

        refcount = self.refcount

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "address": address,
                "type": type_,
                "namespace": namespace,
                "source": source,
                "refcount": refcount,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        address = d.pop("address")

        type_ = d.pop("type")

        namespace = d.pop("namespace")

        source = d.pop("source")

        refcount = d.pop("refcount")

        search_symbols_by_name_response_model_symbols_item_model = cls(
            name=name,
            address=address,
            type_=type_,
            namespace=namespace,
            source=source,
            refcount=refcount,
        )

        search_symbols_by_name_response_model_symbols_item_model.additional_properties = d
        return search_symbols_by_name_response_model_symbols_item_model

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
