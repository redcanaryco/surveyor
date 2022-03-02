import os
from pathlib import Path
from typing import Iterator

from common import Product


# import all files in the 'products' folder
# this is required so that Product.__subclasses__() can resolve all implemented subclasses
# this ensure that new subclasses in 'products' will automatically be picked up
for module in os.listdir(os.path.join(os.path.dirname(__file__), 'products')):
    if module == '__init__.py' or module[-3:] != '.py':
        continue
    __import__('products.' + module[:-3], locals(), globals())
    del module


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
