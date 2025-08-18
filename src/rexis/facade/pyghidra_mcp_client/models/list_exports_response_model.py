from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.list_exports_response_model_exports_item_model import (
        ListExportsResponseModelExportsItemModel,
    )


T = TypeVar("T", bound="ListExportsResponseModel")


@_attrs_define
class ListExportsResponseModel:
    """
    Attributes:
        exports (list['ListExportsResponseModelExportsItemModel']): A list of exports.
    """

    exports: list["ListExportsResponseModelExportsItemModel"]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.list_exports_response_model_exports_item_model import (
            ListExportsResponseModelExportsItemModel,
        )

        exports = []
        for exports_item_data in self.exports:
            exports_item = exports_item_data.to_dict()
            exports.append(exports_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "exports": exports,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.list_exports_response_model_exports_item_model import (
            ListExportsResponseModelExportsItemModel,
        )

        d = dict(src_dict)
        exports = []
        _exports = d.pop("exports")
        for exports_item_data in _exports:
            exports_item = ListExportsResponseModelExportsItemModel.from_dict(exports_item_data)

            exports.append(exports_item)

        list_exports_response_model = cls(
            exports=exports,
        )

        list_exports_response_model.additional_properties = d
        return list_exports_response_model

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
