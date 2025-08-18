from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.list_imports_response_model_imports_item_model import (
        ListImportsResponseModelImportsItemModel,
    )


T = TypeVar("T", bound="ListImportsResponseModel")


@_attrs_define
class ListImportsResponseModel:
    """
    Attributes:
        imports (list['ListImportsResponseModelImportsItemModel']): A list of imports.
    """

    imports: list["ListImportsResponseModelImportsItemModel"]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.list_imports_response_model_imports_item_model import (
            ListImportsResponseModelImportsItemModel,
        )

        imports = []
        for imports_item_data in self.imports:
            imports_item = imports_item_data.to_dict()
            imports.append(imports_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "imports": imports,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.list_imports_response_model_imports_item_model import (
            ListImportsResponseModelImportsItemModel,
        )

        d = dict(src_dict)
        imports = []
        _imports = d.pop("imports")
        for imports_item_data in _imports:
            imports_item = ListImportsResponseModelImportsItemModel.from_dict(imports_item_data)

            imports.append(imports_item)

        list_imports_response_model = cls(
            imports=imports,
        )

        list_imports_response_model.additional_properties = d
        return list_imports_response_model

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
