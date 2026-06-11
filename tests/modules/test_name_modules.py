"""Tests for the v0.4 name modules: Wikipedia, Wikidata, ORCID, CrossRef, OpenSanctions, Permutator."""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.name.crossref import CrossrefSearch
from osint_toolkit.modules.name.opensanctions import OpenSanctionsSearch
from osint_toolkit.modules.name.orcid import OrcidSearch
from osint_toolkit.modules.name.permutator import UsernamePermutator, permutations
from osint_toolkit.modules.name.wikidata import WikidataSearch
from osint_toolkit.modules.name.wikipedia import WikipediaSearch


@pytest.mark.asyncio
async def test_wikipedia_found() -> None:
    mod = WikipediaSearch()
    target = Target(kind=TargetKind.NAME, value="Linus Torvalds")
    async with respx.mock:
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(
                200,
                json={
                    "query": {
                        "searchinfo": {"totalhits": 47},
                        "search": [
                            {
                                "title": "Linus Torvalds",
                                "snippet": "<b>Linus</b> Benedict <b>Torvalds</b> is a software engineer",
                            }
                        ],
                    }
                },
            )
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.FOUND
    assert f.data["matches"][0]["title"] == "Linus Torvalds"
    assert "<b>" not in f.data["matches"][0]["snippet"]  # HTML stripped


@pytest.mark.asyncio
async def test_wikipedia_not_found() -> None:
    mod = WikipediaSearch()
    target = Target(kind=TargetKind.NAME, value="Acrotol Kanyo")
    async with respx.mock:
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json={"query": {"search": []}})
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.NOT_FOUND


@pytest.mark.asyncio
async def test_wikidata_found_with_person_filter() -> None:
    mod = WikidataSearch()
    target = Target(kind=TargetKind.NAME, value="Linus Torvalds")
    async with respx.mock:
        respx.get("https://www.wikidata.org/w/api.php").mock(
            return_value=httpx.Response(
                200,
                json={
                    "search": [
                        {
                            "id": "Q34253",
                            "label": "Linus Torvalds",
                            "description": "Finnish-American software engineer",
                        },
                        {"id": "Q999", "label": "Linus Foundation", "description": "non-profit consortium"},
                    ]
                },
            )
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.FOUND
    assert f.data["people_matches"] >= 1
    assert f.data["top_matches"][0]["qid"] == "Q34253"


@pytest.mark.asyncio
async def test_orcid_found() -> None:
    mod = OrcidSearch()
    target = Target(kind=TargetKind.NAME, value="Kris Angkanaporn")
    async with respx.mock:
        respx.get("https://pub.orcid.org/v3.0/expanded-search/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "num-found": 1,
                    "expanded-result": [
                        {
                            "orcid-id": "0000-0001-2345-6789",
                            "given-names": "Kris",
                            "family-names": "Angkanaporn",
                            "institution-name": ["Chulalongkorn University"],
                        }
                    ],
                },
            )
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.FOUND
    assert f.data["matches"][0]["orcid"] == "0000-0001-2345-6789"


@pytest.mark.asyncio
async def test_crossref_found() -> None:
    mod = CrossrefSearch()
    target = Target(kind=TargetKind.NAME, value="Kris Angkanaporn")
    async with respx.mock:
        respx.get("https://api.crossref.org/works").mock(
            return_value=httpx.Response(
                200,
                json={
                    "message": {
                        "total-results": 12,
                        "items": [
                            {
                                "DOI": "10.1234/example",
                                "title": ["A paper on pet nutrition"],
                                "container-title": ["Vet World"],
                                "published-print": {"date-parts": [[2025]]},
                                "author": [{"given": "Kris", "family": "Angkanaporn"}],
                            }
                        ],
                    }
                },
            )
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.FOUND
    assert f.data["total_results"] == 12
    assert f.data["papers"][0]["year"] == 2025


@pytest.mark.asyncio
async def test_opensanctions_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSANCTIONS_API_KEY", "test-key")
    mod = OpenSanctionsSearch()
    target = Target(kind=TargetKind.NAME, value="John Smith")
    async with respx.mock:
        respx.get("https://api.opensanctions.org/search/default").mock(
            return_value=httpx.Response(200, json={"results": [], "total": {"value": 0}})
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.NOT_FOUND
    assert f.data["clean"] is True


@pytest.mark.asyncio
async def test_opensanctions_skipped_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENSANCTIONS_API_KEY", raising=False)
    mod = OpenSanctionsSearch()
    target = Target(kind=TargetKind.NAME, value="John Smith")
    async with httpx.AsyncClient() as client:
        f = await mod.run(target, client)
    assert f.status == Status.SKIPPED


@pytest.mark.asyncio
async def test_opensanctions_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSANCTIONS_API_KEY", "test-key")
    mod = OpenSanctionsSearch()
    target = Target(kind=TargetKind.NAME, value="Bad Actor")
    async with respx.mock:
        respx.get("https://api.opensanctions.org/search/default").mock(
            return_value=httpx.Response(
                200,
                json={
                    "total": {"value": 1},
                    "results": [
                        {
                            "id": "ofac-12345",
                            "caption": "Bad Actor",
                            "schema": "Person",
                            "datasets": ["us_ofac_sdn"],
                            "properties": {"country": ["IR"], "topics": ["sanction"]},
                        }
                    ],
                },
            )
        )
        async with httpx.AsyncClient() as client:
            f = await mod.run(target, client)
    assert f.status == Status.FOUND
    assert "manual review" in f.data["warning"]


def test_permutator_generates_plausible_handles() -> None:
    perms = permutations("Vishesh Bhatia")
    assert "vishesh.bhatia" in perms
    assert "vbhatia" in perms
    assert "vishesh_bhatia" in perms
    assert "bhatia.vishesh" in perms
    assert len(perms) >= 8


def test_permutator_strips_titles() -> None:
    perms = permutations("Dr. Atthachai Homhuan")
    assert "atthachai.homhuan" in perms
    # 'dr' should not appear as a component
    assert not any("dr" in p.split(".")[0] for p in perms if "." in p)


def test_permutator_with_hint() -> None:
    perms = permutations("John Smith", hint="bkk")
    assert "johnsmithbkk" in perms or "john.smith.bkk" in perms


@pytest.mark.asyncio
async def test_username_permutator_module_emits_finding() -> None:
    mod = UsernamePermutator()
    target = Target(kind=TargetKind.NAME, value="Linus Torvalds")
    async with httpx.AsyncClient() as client:
        f = await mod.run(target, client)
    assert f.status == Status.FOUND
    assert "permutations" in f.data
    assert "linus.torvalds" in f.data["permutations"]
