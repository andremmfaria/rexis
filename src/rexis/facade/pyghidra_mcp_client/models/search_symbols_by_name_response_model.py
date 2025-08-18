from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, Optional, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.search_symbols_by_name_response_model_symbols_item_model import (
        SearchSymbolsByNameResponseModelSymbolsItemModel,
    )


T = TypeVar("T", bound="SearchSymbolsByNameResponseModel")


@_attrs_define
class SearchSymbolsByNameResponseModel:
    """
    Attributes:
        symbols (list['SearchSymbolsByNameResponseModelSymbolsItemModel']): A list of symbols that match the search
            criteria.
    """

    symbols: list["SearchSymbolsByNameResponseModelSymbolsItemModel"]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.search_symbols_by_name_response_model_symbols_item_model import (
            SearchSymbolsByNameResponseModelSymbolsItemModel,
        )

        symbols = []
        for symbols_item_data in self.symbols:
            symbols_item = symbols_item_data.to_dict()
            symbols.append(symbols_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "symbols": symbols,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.search_symbols_by_name_response_model_symbols_item_model import (
            SearchSymbolsByNameResponseModelSymbolsItemModel,
        )

        d = dict(src_dict)
        symbols = []
        _symbols = d.pop("symbols")
        for symbols_item_data in _symbols:
            symbols_item = SearchSymbolsByNameResponseModelSymbolsItemModel.from_dict(
                symbols_item_data
            )

            symbols.append(symbols_item)

        search_symbols_by_name_response_model = cls(
            symbols=symbols,
        )

        search_symbols_by_name_response_model.additional_properties = d
        return search_symbols_by_name_response_model

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
