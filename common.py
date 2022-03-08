import logging
from abc import ABC, abstractmethod
from typing import Tuple, Optional, Any, Union

from help import log_echo


class Product(ABC):
    """
    Base class for surveyor product implementations.

    Subclasses must implement all abstract methods and invoke this class's constructor.
    """
    product: str = None  # a string describing the product (e.g. cbr/cbth/defender/s1)
    profile: str  # the profile is used to authenticate to the target platform
    _results: dict[Union[str, Tuple], list[Tuple[str, str, str, str]]]
    log: logging.Logger
    _tqdm_echo: bool = False

    def __init__(self, product, profile, tqdm_echo: bool = False, **kwargs):
        self.profile = profile
        self.product = product
        self._tqdm_echo = tqdm_echo

        self.log = logging.getLogger(f'surveyor.{self.product}')

        if not self.profile:
            self.profile = 'default'

        self._results = dict()

        self.log.debug(f'Authenticating to {self.product}')
        self._authenticate()
        self.log.debug(f'Authenticated')

    @abstractmethod
    def _authenticate(self) -> None:
        """
        Authenticate to the target product API.
        """
        raise NotImplementedError()

    # noinspection PyMethodMayBeStatic
    def base_query(self) -> dict:
        """
        Get base query parameters for the product.
        """
        return dict()

    @abstractmethod
    def build_query(self, filters: dict) -> Any:
        """
        Build a base query for the product.
        """
        raise NotImplementedError()

    @abstractmethod
    def process_search(self, tag: Union[str, Tuple], base_query: dict, query: str) -> None:
        """
        Perform a process search.
        """
        raise NotImplementedError()

    @abstractmethod
    def nested_process_search(self, tag: Union[str, Tuple], criteria: dict, base_query: dict) -> None:
        """
        Performed a nested process search.
        """
        raise NotImplementedError()

    def has_results(self) -> bool:
        """
        Test whether product has any search results.
        """
        return len(self._results) > 0

    def clear_results(self) -> None:
        """
        Clear all stored results.
        """
        self._results.clear()

    def get_results(self, final_call: bool = True) -> dict[Union[str, Tuple], list[Tuple[str, str, str, str]]]:
        """
        Get results from all process_search and nested_process_search calls.

        :param final_call: Indicates whether this is the final time get_results will be called for this
        set of process searches.

        :returns: A dictionary whose keys represent the tags used to identify searches. The dictionary values
        are lists containing the search results as tuples with members: hostname, username, path, command_line.
        """
        return self._results

    def _add_results(self, results: list[Tuple[str, str, str, str]], tag: Optional[str] = None):
        """
        Add results to the result store.
        """
        if not tag:
            tag = '_default'

        if tag not in self._results:
            self._results[tag] = list()

        self._results[tag].extend(results)

    def _echo(self, message: str, level: int = logging.DEBUG):
        """
        Write a message to STDOUT and the debug log stream.
        """
        log_echo(message, self.log, level, use_tqdm=self._tqdm_echo)
