"""Name module registry."""

from __future__ import annotations

from osint_toolkit.core.module import BaseModule
from osint_toolkit.modules.name.crossref import CrossrefSearch
from osint_toolkit.modules.name.github_search import GithubNameSearch
from osint_toolkit.modules.name.opensanctions import OpenSanctionsSearch
from osint_toolkit.modules.name.orcid import OrcidSearch
from osint_toolkit.modules.name.permutator import UsernamePermutator, permutations
from osint_toolkit.modules.name.wikidata import WikidataSearch
from osint_toolkit.modules.name.wikipedia import WikipediaSearch


def all_name_modules() -> list[BaseModule]:
    return [
        GithubNameSearch(),
        WikipediaSearch(),
        WikidataSearch(),
        OrcidSearch(),
        CrossrefSearch(),
        OpenSanctionsSearch(),
        UsernamePermutator(),
    ]


__all__ = [
    "GithubNameSearch",
    "WikipediaSearch",
    "WikidataSearch",
    "OrcidSearch",
    "CrossrefSearch",
    "OpenSanctionsSearch",
    "UsernamePermutator",
    "permutations",
    "all_name_modules",
]
