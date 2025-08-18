from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.list_cross_references_response_model_cross_references_item_model import (
        ListCrossReferencesResponseModelCrossReferencesItemModel,
    )


T = TypeVar("T", bound="ListCrossReferencesResponseModel")


@_attrs_define
class ListCrossReferencesResponseModel:
    """
    Attributes:
        cross_references (list['ListCrossReferencesResponseModelCrossReferencesItemModel']): A list of cross-references.
    """

    cross_references: list["ListCrossReferencesResponseModelCrossReferencesItemModel"]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.list_cross_references_response_model_cross_references_item_model import (
            ListCrossReferencesResponseModelCrossReferencesItemModel,
        )

        cross_references = []
        for cross_references_item_data in self.cross_references:
            cross_references_item = cross_references_item_data.to_dict()
            cross_references.append(cross_references_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cross_references": cross_references,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.list_cross_references_response_model_cross_references_item_model import (
            ListCrossReferencesResponseModelCrossReferencesItemModel,
        )

        d = dict(src_dict)
        cross_references = []
        _cross_references = d.pop("cross_references")
        for cross_references_item_data in _cross_references:
            cross_references_item = (
                ListCrossReferencesResponseModelCrossReferencesItemModel.from_dict(
                    cross_references_item_data
                )
            )

            cross_references.append(cross_references_item)

        list_cross_references_response_model = cls(
            cross_references=cross_references,
        )

        list_cross_references_response_model.additional_properties = d
        return list_cross_references_response_model

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
