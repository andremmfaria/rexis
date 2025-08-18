from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar, Union, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ListCrossReferencesResponseModelCrossReferencesItemModel")


@_attrs_define
class ListCrossReferencesResponseModelCrossReferencesItemModel:
    """
    Attributes:
        from_address (str): The address where the cross-reference originates.
        to_address (str): The address that is being referenced.
        type_ (str): The type of the cross-reference.
        function_name (Union[None, Unset, str]): The name of the function containing the cross-reference.
    """

    from_address: str
    to_address: str
    type_: str
    function_name: Union[None, Unset, str] = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from_address = self.from_address

        to_address = self.to_address

        type_ = self.type_

        function_name: Union[None, Unset, str]
        if isinstance(self.function_name, Unset):
            function_name = UNSET
        else:
            function_name = self.function_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "from_address": from_address,
                "to_address": to_address,
                "type": type_,
            }
        )
        if function_name is not UNSET:
            field_dict["function_name"] = function_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        from_address = d.pop("from_address")

        to_address = d.pop("to_address")

        type_ = d.pop("type")

        def _parse_function_name(data: object) -> Union[None, Unset, str]:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(Union[None, Unset, str], data)

        function_name = _parse_function_name(d.pop("function_name", UNSET))

        list_cross_references_response_model_cross_references_item_model = cls(
            from_address=from_address,
            to_address=to_address,
            type_=type_,
            function_name=function_name,
        )

        list_cross_references_response_model_cross_references_item_model.additional_properties = d
        return list_cross_references_response_model_cross_references_item_model

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
