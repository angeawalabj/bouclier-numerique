"""Le bug d'origine (Jour 19) : la sous-commande `generate` n'avait
aucune implémentation — elle ne produisait jamais le .docx qu'elle
prétendait générer. Ce test vérifie qu'un vrai fichier est produit.
"""

from docx import Document
from pca_generator import build_pca_data, generate_docx

DEMO_COMPANY = {
    "name": "TestCorp",
    "sector": "Test",
    "employees": 10,
    "revenue_per_hour": 100,
    "dpo": "dpo@testcorp.fr",
    "rssi": "rssi@testcorp.fr",
    "crisis_cell": ["Alice — 0102030405"],
}


def test_generate_docx_produces_a_real_readable_file(tmp_path):
    data = build_pca_data(DEMO_COMPANY)
    output = tmp_path / "pca.docx"

    result_path = generate_docx(data, output)

    assert result_path == output
    assert output.exists()
    assert output.stat().st_size > 1000


def test_generated_docx_contains_the_risk_matrix(tmp_path):
    data = build_pca_data(DEMO_COMPANY)
    output = tmp_path / "pca.docx"
    generate_docx(data, output)

    doc = Document(output)
    full_text = "\n".join(p.text for p in doc.paragraphs)

    assert "TestCorp" in full_text
    for incident in data["incidents"]:
        assert incident["label"] in full_text
