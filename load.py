from typing import Iterator

from common import Product

# these imports must exit for subclass resolution to function
# new subclasses won't be shown unless they are imported here
# new subclasses must have the 'product' attribute
# noinspection PyUnresolvedReferences
from products import (
    microsoft_defender_for_endpoints as defender,
    vmware_cb_enterprise_edr as cbth,
    vmware_cb_response as cbr
)


def _get_subclasses():
    seen = set()

    for subclass in Product.__subclasses__():
        if subclass.product in seen:
            raise ValueError(f'Product {subclass.product} is declared multiple times')

        seen.add(subclass.product)
        yield subclass


def get_product_instance(product: str, **kwargs) -> Product:
    """
    Get an instance of the product implementation matching the specified product string.
    """
    for subclass in Product.__subclasses__():
        if subclass.product == product:
            return subclass(**kwargs)

    raise ValueError(f'Product {product} is not implemented')


def get_products() -> Iterator[str]:
    """
    Get a list of all implemented product strings.
    """
    return (subclass.product for subclass in _get_subclasses())
