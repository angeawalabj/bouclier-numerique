"""Le bug d'origine (Jour 28) : enrich_ip() attribuait un pays, un ASN et
un score de réputation fixes à toute IP commençant par 185/45/194/91 —
une donnée entièrement fabriquée. Ces tests vérifient que l'enrichissement
vient réellement de la base d'IoC du Jour 29, pas d'un préfixe d'adresse.
"""

from soar import SoarActions
from threat_intel import IoC, IoCDatabase


def test_ip_present_in_ioc_db_is_flagged_with_its_real_source(tmp_path):
    db_path = str(tmp_path / "ti.db")
    IoCDatabase(db_path).upsert(
        IoC("ip", "203.0.113.42", "TestFeed", confidence=77,
            severity="ÉLEVÉE", tags=["test"])
    )

    result = SoarActions().enrich_ip("203.0.113.42", ioc_db_path=db_path)

    assert result["known_malicious"] is True
    assert result["source"] == "TestFeed"
    assert result["reputation_score"] == 77


def test_ip_absent_from_ioc_db_is_not_fabricated_as_malicious(tmp_path):
    db_path = str(tmp_path / "ti.db")
    IoCDatabase(db_path)  # base vide

    result = SoarActions().enrich_ip("198.51.100.7", ioc_db_path=db_path)

    assert result["known_malicious"] is False
    assert result["reputation_score"] == 0


def test_private_ip_is_recognized_without_querying_the_db():
    result = SoarActions().enrich_ip("192.168.1.5")
    assert result["is_private"] is True
    assert result["known_malicious"] is False


def test_enrichment_does_not_depend_on_ip_prefix_alone(tmp_path):
    """L'ancien bug marquait TOUTE IP en 185.x comme malveillante. Une
    IP en 185.x absente de la vraie base ne doit plus l'être."""
    db_path = str(tmp_path / "ti.db")
    IoCDatabase(db_path)  # base vide, aucun IoC connu

    result = SoarActions().enrich_ip("185.1.2.3", ioc_db_path=db_path)

    assert result["known_malicious"] is False
