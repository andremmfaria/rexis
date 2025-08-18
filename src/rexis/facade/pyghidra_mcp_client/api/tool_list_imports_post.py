from http import HTTPStatus
from typing import Any, Optional, Union, cast

import httpx

from .. import errors
from ..client import AuthenticatedClient, Client
from ..models.http_validation_error import HTTPValidationError
from ..models.list_imports_form_model import ListImportsFormModel
from ..models.list_imports_response_model import ListImportsResponseModel
from ..types import UNSET, Response


def _get_kwargs(
    *,
    body: ListImportsFormModel,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/list_imports",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: Union[AuthenticatedClient, Client], response: httpx.Response
) -> Optional[Union[HTTPValidationError, Union["ListImportsResponseModel", Any]]]:
    if response.status_code == 200:

        def _parse_response_200(data: object) -> Union["ListImportsResponseModel", Any]:
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                response_200_type_0 = ListImportsResponseModel.from_dict(data)

                return response_200_type_0
            except:  # noqa: E722
                pass
            return cast(Union["ListImportsResponseModel", Any], data)

        response_200 = _parse_response_200(response.json())

        return response_200
    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422
    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: Union[AuthenticatedClient, Client], response: httpx.Response
) -> Response[Union[HTTPValidationError, Union["ListImportsResponseModel", Any]]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ListImportsFormModel,
) -> Response[Union[HTTPValidationError, Union["ListImportsResponseModel", Any]]]:
    """List Imports

     Lists all imported functions and symbols for a specified binary.

        Args:
            binary_name: The name of the binary to list imports from.
            query: An optional query to filter imports by name (regex supported).
            offset: The number of results to skip.
            limit: The maximum number of results to return.

    Args:
        body (ListImportsFormModel):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Union[HTTPValidationError, Union['ListImportsResponseModel', Any]]]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: ListImportsFormModel,
) -> Optional[Union[HTTPValidationError, Union["ListImportsResponseModel", Any]]]:
    """List Imports

     Lists all imported functions and symbols for a specified binary.

        Args:
            binary_name: The name of the binary to list imports from.
            query: An optional query to filter imports by name (regex supported).
            offset: The number of results to skip.
            limit: The maximum number of results to return.

    Args:
        body (ListImportsFormModel):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Union[HTTPValidationError, Union['ListImportsResponseModel', Any]]
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ListImportsFormModel,
) -> Response[Union[HTTPValidationError, Union["ListImportsResponseModel", Any]]]:
    """List Imports

     Lists all imported functions and symbols for a specified binary.

        Args:
            binary_name: The name of the binary to list imports from.
            query: An optional query to filter imports by name (regex supported).
            offset: The number of results to skip.
            limit: The maximum number of results to return.

    Args:
        body (ListImportsFormModel):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Union[HTTPValidationError, Union['ListImportsResponseModel', Any]]]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ListImportsFormModel,
) -> Optional[Union[HTTPValidationError, Union["ListImportsResponseModel", Any]]]:
    """List Imports

     Lists all imported functions and symbols for a specified binary.

        Args:
            binary_name: The name of the binary to list imports from.
            query: An optional query to filter imports by name (regex supported).
            offset: The number of results to skip.
            limit: The maximum number of results to return.

    Args:
        body (ListImportsFormModel):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Union[HTTPValidationError, Union['ListImportsResponseModel', Any]]
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
