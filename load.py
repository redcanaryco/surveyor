import os
from typing import Type, Iterable

from common import Product

# import all files in the 'products' folder
# this is required so that Product.__subclasses__() can resolve all implemented subclasses
for module in os.listdir(os.path.join(os.path.dirname(__file__), 'products')):
    if module == '__init__.py' or module[-3:] != '.py':
        continue

    sub_module = module[:-3]

    __import__('products.' + sub_module, locals(), globals())
    del module


def _get_subclasses() -> list[Type[Product]]:
    """
    Retrieve all subclasses of the "Product" class.
    """
    seen = set()

    for subclass in Product.__subclasses__():
        # ensure two products don't have the same product string
        if subclass.product in seen:
            raise ValueError(f'Product {subclass.product} is declared multiple times')

        seen.add(subclass.product)
        yield subclass


def get_product_instance(product: str, **kwargs) -> Product:
    """
    Get an instance of the product implementation matching the specified product string.
    """
    for subclass in _get_subclasses():
        if subclass.product == product:
            return subclass(**kwargs)

    raise ValueError(f'Product {product} is not implemented')


def get_products() -> Iterable[str]:
    """
    Get a list of all implemented product strings.
    """
    return [subclass.product for subclass in _get_subclasses()] + ['cbr']
