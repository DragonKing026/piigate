"""Synthetic patient data for the piigate tests — EVERYTHING IS INVENTED (never real PHI).

First names are common Polish first names (the detector needs them); surnames, streets, towns, drugs and the
pharmacy are made-up words. PESEL numbers are generated with a valid checksum for invented dates; prescription
and phone numbers are random from a fixed seed; e-mails use the reserved .test domain; the seller NIP is a test
number (valid checksum). `PATIENTS` and `values()` list the values that must NEVER appear in filter output.
The test inputs are Polish on purpose: the product detects Polish personal data.
"""

import random
import zipfile
from email.message import EmailMessage
from pathlib import Path
from xml.sax.saxutils import escape

RNG = random.Random(20261019)


def _pesel(year: int, month: int, day: int) -> str:
    m = month + (20 if year >= 2000 else 0)
    base = f"{year % 100:02d}{m:02d}{day:02d}{RNG.randint(0, 9999):04d}"
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return base + str((10 - sum(int(c) * w for c, w in zip(base, weights)) % 10) % 10)


def _patient(first_name, surname, street, number, code, city, birth, drug):
    r, m, d = birth
    return {
        "first_name": first_name,
        "surname": surname,
        "street": street,
        "address": f"ul. {street} {number}",
        "postal_code": code,
        "city": city,
        "birth_date": f"{d:02d}.{m:02d}.{r}",
        "pesel": _pesel(r, m, d),
        "phone": f"{RNG.choice('5678')}{RNG.randint(10, 99)} {RNG.randint(100, 999)} {RNG.randint(100, 999)}",
        "email": f"{first_name.lower()[:3]}.{RNG.randint(100, 999)}@przyklad-poczta.test",
        "drug": drug,
        "prescription": "".join(str(RNG.randint(0, 9)) for _ in range(22)),
    }


PATIENTS = [
    _patient("Genowefa", "Przykładowska", "Wymyślona", "7/12", "99-101", "Zmyślinek", (1962, 4, 3), "Atrapolin"),
    _patient("Zdzisław", "Atrapowicz", "Nieistniejąca", "15", "98-202", "Fikcyjnowo", (1979, 11, 27), "Placebinum"),
    _patient("Bogumiła", "Testowska", "Kapuściana", "3a/4", "97-303", "Wydumanowo", (2003, 2, 14), "Udawanol"),
    _patient("Eustachy", "Pomidorek", "Kalafiorowa", "88", "96-404", "Marchwin", (1991, 7, 9), "Zmyślocyna"),
]


def values() -> list[str]:
    """Every substituted value — none of them may appear after passing through the filter."""
    w = []
    for p in PATIENTS:
        w += [
            p["first_name"],
            p["surname"],
            p["street"],
            p["city"],
            p["birth_date"],
            p["pesel"],
            p["phone"],
            p["phone"].replace(" ", ""),
            p["email"],
            p["drug"],
            p["prescription"],
            p["postal_code"],
        ]
    return w


# --- mail -----------------------------------------------------------------------------------------


def mail_body(p: dict, q: dict) -> str:
    return f"""Dzień dobry,

w załączeniu przesyłam zestawienie recept z października. Proszę o pilną weryfikację dwóch pozycji.

1) Pani {p["first_name"]} {p["surname"]} (ur. {p["birth_date"]}, PESEL {p["pesel"]}), zam. {p["address"]}, {p["postal_code"]} {p["city"]},
   odebrała lek {p["drug"]} 20 mg na receptę nr {p["prescription"]}. Pani {p["surname"]} prosi o kontakt pod numerem
   {p["phone"]} albo mailowo: {p["email"]}.

2) Pan {q["first_name"]} {q["surname"]}, ur. {q["birth_date"]}, tel. {q["phone"]}, adres: {q["address"]}, {q["postal_code"]} {q["city"]}.
   Rp. {q["prescription"]} — {q["drug"]} 5 mg, 30 tabl. Recepta wystawiona dla pacjenta {q["first_name"]} {q["surname"]}.

Z poważaniem
Apteka Testowa Sp. z o.o.
"""


def write_mail(dest: Path, attachments: list[Path]) -> Path:
    p, q = PATIENTS[0], PATIENTS[1]
    m = EmailMessage()
    m["From"] = f"{PATIENTS[2]['first_name']} {PATIENTS[2]['surname']} <{PATIENTS[2]['email']}>"
    m["To"] = "rozliczenia@przyklad-firma.test"
    m["Subject"] = f"Recepty — {p['surname']}, {q['surname']}"
    m["Date"] = "Mon, 19 Oct 2026 10:00:00 +0200"
    m.set_content(mail_body(p, q))
    for z in attachments:
        m.add_attachment(z.read_bytes(), maintype="application", subtype="octet-stream", filename=z.name)
    dest.write_bytes(bytes(m))
    return dest


# --- spreadsheets --------------------------------------------------------------------------------------

HEADERS = ["Pacjent", "PESEL", "Data urodzenia", "Adres", "Telefon", "Lek", "Numer recepty", "Kwota"]


def rows() -> list[list[str]]:
    return [
        [
            f"{p['first_name']} {p['surname']}",
            p["pesel"],
            p["birth_date"],
            f"{p['address']}, {p['postal_code']} {p['city']}",
            p["phone"],
            p["drug"],
            p["prescription"],
            f"{RNG.randint(5, 300)},{RNG.randint(10, 99)}",
        ]
        for p in PATIENTS
    ]


def write_csv(dest: Path) -> Path:
    dest.write_text("\n".join(";".join(w) for w in [HEADERS] + rows()) + "\n", encoding="utf-8")
    return dest


def write_xlsx(dest: Path) -> Path:
    """Minimal XLSX (no libraries): sharedStrings, a date style (numFmtId 14) for the birth date stored as a number."""
    texts: list[str] = []

    def s(t: str) -> int:
        if t not in texts:
            texts.append(t)
        return texts.index(t)

    def col(i: int) -> str:
        return chr(65 + i)

    row_xml = []
    for r, w in enumerate([HEADERS] + rows(), 1):
        cells = []
        for c, v in enumerate(w):
            ref = f"{col(c)}{r}"
            if r > 1 and c == 2:  # birth date: Excel serial number + date style
                d, m, y = map(int, v.split("."))
                import datetime

                serial = (datetime.date(y, m, d) - datetime.date(1899, 12, 30)).days
                cells.append(f'<c r="{ref}" s="1"><v>{serial}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="s"><v>{s(v)}</v></c>')
        row_xml.append(f'<row r="{r}">{"".join(cells)}</row>')
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": f'<?xml version="1.0" encoding="UTF-8"?><workbook {ns} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Recepty {escape(PATIENTS[3]["surname"])}" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
        "xl/styles.xml": f'<?xml version="1.0" encoding="UTF-8"?><styleSheet {ns}><cellXfs count="2"><xf numFmtId="0"/><xf numFmtId="14" applyNumberFormat="1"/></cellXfs></styleSheet>',
        "xl/worksheets/sheet1.xml": f'<?xml version="1.0" encoding="UTF-8"?><worksheet {ns}><sheetData>{"".join(row_xml)}</sheetData></worksheet>',
        "xl/sharedStrings.xml": f'<?xml version="1.0" encoding="UTF-8"?><sst {ns} count="{len(texts)}" uniqueCount="{len(texts)}">'
        + "".join(f"<si><t>{escape(t)}</t></si>" for t in texts)
        + "</sst>",
    }
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for n, t in files.items():
            z.writestr(n, t)
    return dest


# --- PDF (by hand: Helvetica + /Differences with Polish glyphs) ----------------------------------

POLISH_GLYPHS = {
    "ą": "aogonek",
    "ć": "cacute",
    "ę": "eogonek",
    "ł": "lslash",
    "ń": "nacute",
    "ó": "oacute",
    "ś": "sacute",
    "ź": "zacute",
    "ż": "zdotaccent",
    "Ą": "Aogonek",
    "Ć": "Cacute",
    "Ę": "Eogonek",
    "Ł": "Lslash",
    "Ń": "Nacute",
    "Ó": "Oacute",
    "Ś": "Sacute",
    "Ź": "Zacute",
    "Ż": "Zdotaccent",
    "—": "emdash",
}
CODES = {ch: 128 + i for i, ch in enumerate(POLISH_GLYPHS)}


def _pdf_text(t: str) -> str:
    result = []
    for ch in t:
        if ch in CODES:
            result.append(f"\\{CODES[ch]:03o}")
        elif ch in "()\\":
            result.append("\\" + ch)
        else:
            result.append(ch)
    return "".join(result)


def invoice_lines() -> list[str]:
    lines = [
        "FAKTURA VAT nr TEST/2026/0001 (dokument przykładowy)",
        "Sprzedawca: Apteka Testowa Sp. z o.o., NIP 123-456-00-07",
        "Data wystawienia: 31.10.2026",
        "",
        "Zestawienie recept refundowanych:",
        "",
    ]
    for p in PATIENTS:
        lines += [
            f"Pacjent: {p['first_name']} {p['surname']}   PESEL: {p['pesel']}   ur. {p['birth_date']}",
            f"Adres: {p['address']}, {p['postal_code']} {p['city']}   tel. {p['phone']}",
            f"Lek: {p['drug']} 10 mg   nr recepty: {p['prescription']}",
            "",
        ]
    lines += ["Razem do zapłaty: 1 234,56 zł"]
    return lines


def write_pdf(dest: Path) -> Path:
    diff = " ".join(f"{CODES[ch]} /{g}" for ch, g in POLISH_GLYPHS.items())
    stream = "BT /F1 10 Tf 50 800 Td 14 TL\n" + "".join(f"({_pdf_text(ln)}) '\n" for ln in invoice_lines()) + "ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> "
            "/Contents 5 0 R >>"
        ),
        (
            f"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding "
            f"/BaseEncoding /WinAnsiEncoding /Differences [{diff}] >> >>"
        ),
        f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream",
    ]
    output = b"%PDF-1.4\n"
    offsets = []
    for i, o in enumerate(objects, 1):
        offsets.append(len(output))
        output += f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1")
    xref = len(output)
    output += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    output += "".join(f"{p:010d} 00000 n \n" for p in offsets).encode()
    output += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    dest.write_bytes(output)
    return dest


# --- SQL results (as printed in a terminal) -----------------------------------------------------------------


def sql_symfony() -> str:
    """bin/console dbal:run-sql (SymfonyStyle::table)."""
    col = ["id", "imie", "nazwisko", "pesel", "telefon", "lek"]  # Polish column names, as in a real schema
    data = [[str(i + 1), p["first_name"], p["surname"], p["pesel"], p["phone"], p["drug"]] for i, p in enumerate(PATIENTS)]
    widths = [max(len(k), *(len(w[j]) for w in data)) for j, k in enumerate(col)]
    dash_line = " " + " ".join("-" * s for s in widths) + " "
    row = lambda w: " " + " ".join(v.ljust(s) for v, s in zip(w, widths)) + " "
    return "\n".join(["", dash_line, row(col), dash_line] + [row(w) for w in data] + [dash_line, ""])


def sql_var_dump() -> str:
    """Older dbal:run-sql / doctrine:query:sql (var_dump)."""
    out_lines = [f"array({len(PATIENTS)}) {{"]
    for i, p in enumerate(PATIENTS):
        out_lines.append(f"  [{i}]=>\n  array(4) {{")
        for column, key in (("imie", "first_name"), ("nazwisko", "surname"), ("pesel", "pesel"), ("telefon", "phone")):
            out_lines.append(f'    ["{column}"]=>\n    string({len(p[key].encode())}) "{p[key]}"')
        out_lines.append("  }")
    out_lines.append("}")
    return "\n".join(out_lines) + "\n"


def sql_psql() -> str:
    col = ["imie", "nazwisko", "miasto", "recepta"]
    data = [[p[k] for k in ("first_name", "surname", "city", "prescription")] for p in PATIENTS]
    widths = [max(len(k), *(len(w[j]) for w in data)) for j, k in enumerate(col)]
    row = lambda w: " " + " | ".join(v.ljust(s) for v, s in zip(w, widths))
    return "\n".join(
        [row(col), "-" + "-+-".join("-" * s for s in widths) + "-"]
        + [row(w) for w in data]
        + [f"({len(data)} rows)", ""]
    )


def write_all(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "csv": write_csv(directory / "recepty-pazdziernik.csv"),
        "xlsx": write_xlsx(directory / f"Recepty_{PATIENTS[3]['surname']}.xlsx"),
        "pdf": write_pdf(directory / "faktura-TEST-2026-0001.pdf"),
    }
    files["eml"] = write_mail(directory / "mail-recepty.eml", [files["xlsx"], files["pdf"]])
    return files


if __name__ == "__main__":
    import sys

    for k, v in write_all(Path(sys.argv[1] if len(sys.argv) > 1 else "test-data")).items():
        print(k, v)
