import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, Optional, Any

from help import log_echo


class AuthenticationError(Exception):
    pass


@dataclass(eq=True, frozen=True)
class Tag:
    tag: str
    data: Optional[str] = None


@dataclass(eq=True, frozen=True)
class Result:
    hostname: str
    username: str
    path: str
    command_line: str
    other_data: Optional[Tuple] = None  # use tuples as they are immutable


class Product(ABC):
    """
    Base class for surveyor product implementations.

    Subclasses must implement all abstract methods and invoke this class's constructor.
    """
    product: Optional[str] = None  # a string describing the product (e.g. cbr/cbth/defender/s1)
    profile: str  # the profile is used to authenticate to the target platform
    _results: dict[Tag, list[Result]]
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
    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        """
        Perform a process search.
        """
        raise NotImplementedError()

    @abstractmethod
    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
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

    def get_results(self, final_call: bool = True) -> dict[Tag, list[Result]]:
        """
        Get results from all process_search and nested_process_search calls.

        :param final_call: Indicates whether this is the final time get_results will be called for this
        set of process searches.

        :returns: A dictionary whose keys represent the tags used to identify searches. The dictionary values
        are lists containing the search results as tuples with members: hostname, username, path, command_line.
        """
        return self._results

    # noinspection PyMethodMayBeStatic
    def get_other_row_headers(self) -> list[str]:
        """
        Retrieve any additional headers this product includes in results.
        """
        return list()

    def _add_results(self, results: list[Result], tag: Optional[Tag] = None):
        """
        Add results to the result store.
        """
        if not tag:
            tag = Tag('_default')

        if tag not in self._results:
            self._results[tag] = list()

        self._results[tag].extend(results)

    def _echo(self, message: str, level: int = logging.DEBUG):
        """
        Write a message to STDOUT and the debug log stream.
        """
        log_echo(message, self.log, level, use_tqdm=self._tqdm_echo)

def sigma_translation(product: str, sigma_rules: list) -> dict:
    supports_json_ouput = True

    try:
        from sigma.collection import SigmaCollection # type: ignore
        from sigma.plugins import SigmaPluginDirectory # type: ignore
        plugins = SigmaPluginDirectory.default_plugin_directory()
    except Exception as e:
        raise e

    if product in ('cbr','cbc'):
        plugins.get_plugin_by_id('carbonblack').install()
        from sigma.backends.carbonblack import CarbonBlackBackend # type: ignore

        if product == 'cbr':
            from sigma.pipelines.carbonblack import CarbonBlackResponse_pipeline as cb_pipeline # type: ignore
        else:
            from sigma.pipelines.carbonblack import CarbonBlack_pipeline as cb_pipeline # type: ignore

        backend = CarbonBlackBackend(cb_pipeline())
    elif product == 's1':
        plugins.get_plugin_by_id('sentinelone').install()
        from sigma.backends.sentinel_one import SentinelOneBackend # type: ignore
        backend = SentinelOneBackend()
    elif product == 'dfe':
        supports_json_ouput = False
        plugins.get_plugin_by_id('microsoft365defender').install()
        from sigma.backends.microsoft365defender import Microsoft365DefenderBackend # type: ignore
        backend = Microsoft365DefenderBackend()

    rule_collection = SigmaCollection.load_ruleset(sigma_rules)
    if supports_json_ouput:
        return backend.convert(rule_collection, "json")
    else:
        results: dict = {"queries":[]}
        for r in rule_collection:
            results['queries'].append({
                'query': backend.convert_rule(r)[0],
                'id': r.id,
                'title': r.title,
                'description': r.description
            })
        return results
