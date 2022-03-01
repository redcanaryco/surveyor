import csv
import logging
from abc import ABC, abstractmethod


class Product(ABC):
    product: str = None  # a string describing the product (e.g. cbr/cbth/defender/s1)
    profile: str  # the profile is used to authenticate to the target platform
    log: logging.Logger

    def __init__(self, product, profile):
        self.profile = profile
        self.product = product

        self.log = logging.getLogger(f'surveyor.{self.product}')

        if not self.profile:
            self.profile = 'default'

        self.log.debug(f'Authenticating to {self.product}')
        self._authenticate()
        self.log.debug(f'Authenticated')

    @abstractmethod
    def _authenticate(self):
        """
        Authenticate to the target product API.
        """
        raise NotImplementedError()

    # noinspection PyMethodMayBeStatic
    def base_query(self):
        """
        Get base query parameters for the product.
        """
        return dict()

    @abstractmethod
    def build_query(self, filters: dict):
        """
        Build a base query for the product.
        """
        raise NotImplementedError()

    @abstractmethod
    def process_search(self, base_query, query):
        """
        Perform a process search.
        """
        raise NotImplementedError()

    @abstractmethod
    def nested_process_search(self, criteria, base_query):
        """
        Performed a nested process search.
        """
        raise NotImplementedError()
