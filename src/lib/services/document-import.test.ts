import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { deflateSync } from "node:zlib";

import {
  PDFDocument,
  PDFName,
  PDFNull,
  PDFString,
  StandardFonts,
} from "pdf-lib";

import { MAX_PDF_PAGES } from "../types/domain.ts";
import {
  DocumentImportError,
  getPdfImportErrorMessage,
  importPdfDocument,
} from "./document-import.ts";

// A one-page PDF that needs the password "demo-user" to open (AES-256).
// Same fixture as src/lib/pdf-preview-error.test.ts.
const PASSWORD_PDF_BASE64 =
  "JVBERi0xLjMKJeLjz9MKMSAwIG9iago8PAovUHJvZHVjZXIgPDhlMjlhMmMyYTUwZjViYjUwNTFkZjhhOWEzNmZlODgyMTMzZDNmMmJiN2M4OTgyNTUyMmQ3ZGFkOGEwYmY5MzQ+Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9UeXBlIC9QYWdlcwovQ291bnQgMQovS2lkcyBbIDQgMCBSIF0KPj4KZW5kb2JqCjMgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDIgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9UeXBlIC9QYWdlCi9SZXNvdXJjZXMgPDwKPj4KL01lZGlhQm94IFsgMC4wIDAuMCA2MTIgNzkyIF0KL1BhcmVudCAyIDAgUgo+PgplbmRvYmoKNSAwIG9iago8PAovViA1Ci9SIDYKL0xlbmd0aCAyNTYKL1AgNDI5NDk2NzI5MgovRmlsdGVyIC9TdGFuZGFyZAovTyA8MmRhZTg3MThkOTdhMTE3OGQ5M2JlNTk3MTgzZTc4MWRiNmUwNDkwMzliZmQyNzYzMGI3MDI0MTFmY2UzMjY2YTExYzFkZTdlNjNjNjZjMmI2OTI3YTc5OTYxMjQ4N2EzPgovVSA8Mjk0N2JiY2NjM2ZjMzVjOTAzZDAyYmMxMDc4OWM4YzdiMWEzNDZiNzAzMGVmNzhhNzI3OTE2YjljNjg0Y2JjMTYxM2I1ZDVlNmEwZjI2ZDU5YWRmMzRkZDJmZDg5OWYzPgovQ0YgPDwKL1N0ZENGIDw8Ci9BdXRoRXZlbnQgL0RvY09wZW4KL0NGTSAvQUVTVjMKL0xlbmd0aCAzMgo+Pgo+PgovU3RtRiAvU3RkQ0YKL1N0ckYgL1N0ZENGCi9PRSA8MTY3YmZlMzgwMDczOGVjNGZjZjBhNjY0ZmJjY2E5YTg5NDA1M2YxYzMxZDdiYzIyNGNhMjNkNzM3MjBhNTQ4ZD4KL1VFIDw5OTY4ZTIwZjdhNWE0ZmE0YjU1NzYxOWNmNzljMGZhMGRhNWYyOTNmMjA3MzgzM2RlN2M5NDJlMWRjOWM4NDBmPgovUGVybXMgPDYxNGVlYjdiZmFhNDIxNWUzZDFlMWM5ZWY5MTgxMjAzPgo+PgplbmRvYmoKeHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDAxMTMgMDAwMDAgbiAKMDAwMDAwMDE3MiAwMDAwMCBuIAowMDAwMDAwMjIxIDAwMDAwIG4gCjAwMDAwMDAzMTUgMDAwMDAgbiAKdHJhaWxlcgo8PAovU2l6ZSA2Ci9Sb290IDMgMCBSCi9JbmZvIDEgMCBSCi9JRCBbIDwzNTYxMzEzMjYyMzc2NDM3MzgzNTYxMzY2NDM1MzUzNzM1MzYzOTYyNjIzNzMwNjQzMjM0MzIzMjYxMzczMDM5PiA8MzU2MTMxMzI2MjM3NjQzNzM4MzU2MTM2NjQzNTM1MzczNTM2Mzk2MjYyMzczMDY0MzIzNDMyMzI2MTM3MzAzOT4gXQovRW5jcnlwdCA1IDAgUgo+PgpzdGFydHhyZWYKODcwCiUlRU9GCg==";

const PDF_PADDING = Buffer.from(
  "28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a",
  "hex",
);

function rc4(key: Uint8Array, data: Uint8Array): Buffer {
  const s = new Uint8Array(256);

  for (let i = 0; i < 256; i += 1) {
    s[i] = i;
  }

  let j = 0;

  for (let i = 0; i < 256; i += 1) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    const tmp = s[i]!;
    s[i] = s[j]!;
    s[j] = tmp;
  }

  const out = Buffer.alloc(data.length);
  let i = 0;
  j = 0;

  for (let k = 0; k < data.length; k += 1) {
    i = (i + 1) & 0xff;
    j = (j + s[i]!) & 0xff;
    const tmp = s[i]!;
    s[i] = s[j]!;
    s[j] = tmp;
    out[k] = data[k]! ^ s[(s[i]! + s[j]!) & 0xff]!;
  }

  return out;
}

/**
 * Builds a valid one-page PDF encrypted with Standard Security Handler (V=1,
 * R=2, 40-bit RC4) using an empty user password and an owner password that
 * restricts modifications. Readers like PDF.js open it without prompting, but
 * the document still carries a trailer /Encrypt dictionary.
 */
function buildOwnerPasswordOnlyPdf(): Uint8Array {
  const idBytes = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
  const ownerPassword = Buffer.from("owner-secret", "latin1");
  const paddedOwner = Buffer.concat([ownerPassword, PDF_PADDING]).subarray(
    0,
    32,
  );
  const ownerKey = createHash("md5")
    .update(paddedOwner)
    .digest()
    .subarray(0, 5);
  const oEntry = rc4(ownerKey, PDF_PADDING);

  // Permissions: allow printing only (disallow editing/signing).
  const permissions = -3904;
  const pBytes = Buffer.alloc(4);
  pBytes.writeInt32LE(permissions, 0);

  // Empty user password -> padded with PDF_PADDING.
  const encKey = createHash("md5")
    .update(PDF_PADDING)
    .update(oEntry)
    .update(pBytes)
    .update(idBytes)
    .digest()
    .subarray(0, 5);
  const uEntry = rc4(encKey, PDF_PADDING);

  const objects = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Count 1 /Kids [ 3 0 R ] >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Resources << >> >>\nendobj\n",
    `4 0 obj\n<< /Filter /Standard /V 1 /R 2 /Length 40 /P ${String(permissions)} /O <${oEntry.toString("hex")}> /U <${uEntry.toString("hex")}> >>\nendobj\n`,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];

  for (const obj of objects) {
    offsets.push(Buffer.byteLength(pdf, "latin1"));
    pdf += obj;
  }

  const xrefOffset = Buffer.byteLength(pdf, "latin1");
  pdf += `xref\n0 ${String(objects.length + 1)}\n`;
  pdf += "0000000000 65535 f \n";

  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }

  const idHex = idBytes.toString("hex");
  pdf += `trailer\n<< /Size ${String(objects.length + 1)} /Root 1 0 R /ID [ <${idHex}> <${idHex}> ] /Encrypt 4 0 R >>\n`;
  pdf += `startxref\n${String(xrefOffset)}\n%%EOF\n`;

  return new Uint8Array(Buffer.from(pdf, "latin1"));
}

function buildMinimalPdfWithTrailer(
  trailerExtra: string,
  extraObjects: string[] = [],
): Uint8Array {
  const objects = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Count 1 /Kids [ 3 0 R ] >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Resources << >> >>\nendobj\n",
    ...extraObjects,
  ];

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];

  for (const obj of objects) {
    offsets.push(Buffer.byteLength(pdf, "latin1"));
    pdf += obj;
  }

  const xrefOffset = Buffer.byteLength(pdf, "latin1");
  pdf += `xref\n0 ${String(objects.length + 1)}\n`;
  pdf += "0000000000 65535 f \n";

  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }

  pdf += `trailer\n<< /Size ${String(objects.length + 1)} /Root 1 0 R ${trailerExtra} >>\n`;
  pdf += `startxref\n${String(xrefOffset)}\n%%EOF\n`;

  return new Uint8Array(Buffer.from(pdf, "latin1"));
}

function buildXrefStreamEncryptedPdf(): Uint8Array {
  const objects = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Count 1 /Kids [ 3 0 R ] >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 612 792 ] /Resources << >> >>\nendobj\n",
    "4 0 obj\n<< /Filter /Standard /V 1 /R 2 /Length 40 /P -44 /O <00> /U <00> >>\nendobj\n",
  ];

  const header = Buffer.from("%PDF-1.5\n", "latin1");
  const chunks: Buffer[] = [header];
  const offsets: number[] = [];
  let cursor = header.length;

  for (const obj of objects) {
    offsets.push(cursor);
    const buf = Buffer.from(obj, "latin1");
    chunks.push(buf);
    cursor += buf.length;
  }

  const xrefOffset = cursor;
  // W = [1 2 1] -> 4 bytes per entry for objects 0..5.
  const rawXref = Buffer.alloc(6 * 4);
  // 0: free
  rawXref[0] = 0;
  // 1..4: in-use objects
  offsets.forEach((offset, index) => {
    const base = (index + 1) * 4;
    rawXref[base] = 1;
    rawXref.writeUInt16BE(offset, base + 1);
    rawXref[base + 3] = 0;
  });
  // 5: xref stream itself
  rawXref[5 * 4] = 1;
  rawXref.writeUInt16BE(xrefOffset, 5 * 4 + 1);
  rawXref[5 * 4 + 3] = 0;

  const compressedXref = deflateSync(rawXref);
  const xrefPrefix = Buffer.from(
    `5 0 obj\n<< /Type /XRef /Size 6 /W [ 1 2 1 ] /Root 1 0 R /Encrypt 4 0 R /Filter /FlateDecode /Length ${String(compressedXref.length)} >>\nstream\n`,
    "latin1",
  );
  const xrefSuffix = Buffer.from(
    `\nendstream\nendobj\nstartxref\n${String(xrefOffset)}\n%%EOF\n`,
    "latin1",
  );

  chunks.push(xrefPrefix, compressedXref, xrefSuffix);

  return new Uint8Array(Buffer.concat(chunks));
}

async function pdfWithPages(count: number): Promise<Uint8Array> {
  const document = await PDFDocument.create();

  for (let page = 0; page < count; page += 1) {
    document.addPage([612, 792]);
  }

  return document.save();
}

async function pdfWithUncompressedContentStream(
  content: string,
): Promise<Uint8Array> {
  const document = await PDFDocument.create();
  const page = document.addPage([612, 792]);
  const font = await document.embedFont(StandardFonts.Helvetica);

  // Register font on the page first so /F1 is available in page resources.
  page.drawText("ok", { font, size: 12, x: 72, y: 740 });

  const rawStream = document.context.stream(content);
  const rawStreamRef = document.context.register(rawStream);
  page.node.set(PDFName.of("Contents"), rawStreamRef);

  return document.save({ useObjectStreams: false });
}

test("a PDF with more pages than the limit is refused, one at the limit is taken", async () => {
  await assert.rejects(
    importPdfDocument({
      body: await pdfWithPages(MAX_PDF_PAGES + 1),
      contentType: "application/pdf",
      filename: "many.pdf",
    }),
    (error: unknown) =>
      error instanceof DocumentImportError && error.code === "too_many_pages",
  );

  const imported = await importPdfDocument({
    body: await pdfWithPages(MAX_PDF_PAGES),
    contentType: "application/pdf",
    filename: "long.pdf",
  });

  assert.equal(imported.pageCount, MAX_PDF_PAGES);
});

async function pdfWithLiteralSubject(subject: string): Promise<Uint8Array> {
  const document = await PDFDocument.create();
  document.addPage([612, 792]);

  // Write /Subject as a literal PDF string (the form Acrobat, LibreOffice,
  // Quartz, etc. emit for ASCII metadata) so the raw bytes carry the text
  // verbatim rather than UTF-16BE hex.
  const infoDict = document.context.obj({
    Subject: PDFString.of(subject),
  });
  document.context.trailerInfo.Info = document.context.register(infoDict);

  return document.save({ useObjectStreams: false });
}

test("an unlocked PDF whose subject contains /Encrypt imports cleanly (issue #221)", async () => {
  const literalBody = await pdfWithLiteralSubject(
    "Notes on the /Encrypt dictionary",
  );

  assert.ok(
    Buffer.from(literalBody).toString("latin1").includes("/Encrypt"),
    "expected raw PDF bytes to contain literal /Encrypt",
  );

  const importedLiteral = await importPdfDocument({
    body: literalBody,
    contentType: "application/pdf",
    filename: "subject-encrypt.pdf",
  });

  assert.equal(importedLiteral.encrypted, false);
  assert.equal(importedLiteral.pureXfa, false);
  assert.equal(importedLiteral.pageCount, 1);

  // Also verify a PDF saved via pdf-lib's setSubject (UTF-16BE hex string).
  const hexDoc = await PDFDocument.create();
  hexDoc.addPage([612, 792]);
  hexDoc.setSubject("Notes on the /Encrypt dictionary");
  const importedHex = await importPdfDocument({
    body: await hexDoc.save({ useObjectStreams: false }),
    contentType: "application/pdf",
    filename: "subject-encrypt-hex.pdf",
  });

  assert.equal(importedHex.encrypted, false);
  assert.equal(importedHex.pageCount, 1);
});

test("an unlocked PDF whose subject contains /XFA imports cleanly (issue #222)", async () => {
  const literalBody = await pdfWithLiteralSubject("Notes on legacy /XFA forms");

  assert.ok(
    Buffer.from(literalBody).toString("latin1").includes("/XFA"),
    "expected raw PDF bytes to contain literal /XFA",
  );

  const importedLiteral = await importPdfDocument({
    body: literalBody,
    contentType: "application/pdf",
    filename: "subject-xfa.pdf",
  });

  assert.equal(importedLiteral.encrypted, false);
  assert.equal(importedLiteral.pureXfa, false);
  assert.equal(importedLiteral.pageCount, 1);

  const hexDoc = await PDFDocument.create();
  hexDoc.addPage([612, 792]);
  hexDoc.setSubject("Notes on legacy /XFA forms");
  const importedHex = await importPdfDocument({
    body: await hexDoc.save({ useObjectStreams: false }),
    contentType: "application/pdf",
    filename: "subject-xfa-hex.pdf",
  });

  assert.equal(importedHex.pureXfa, false);
  assert.equal(importedHex.pageCount, 1);
});

test("an unlocked PDF with /Encrypt and /XFA in page text and content stream imports cleanly", async () => {
  const body = await pdfWithUncompressedContentStream(
    "BT /F1 12 Tf 72 720 Td (Reviewing /Encrypt and /XFA specifications) Tj ET",
  );
  const raw = Buffer.from(body).toString("latin1");

  assert.ok(raw.includes("/Encrypt"));
  assert.ok(raw.includes("/XFA"));

  const imported = await importPdfDocument({
    body,
    contentType: "application/pdf",
    filename: "body-keywords.pdf",
  });

  assert.equal(imported.encrypted, false);
  assert.equal(imported.pureXfa, false);
  assert.equal(imported.pageCount, 1);
});

test("a standard AcroForm PDF without an /XFA entry imports cleanly even when field text mentions /XFA", async () => {
  const document = await PDFDocument.create();
  const page = document.addPage([612, 792]);
  const form = document.getForm();
  const field = form.createTextField("notes");
  field.addToPage(page, { height: 24, width: 200, x: 72, y: 700 });
  field.acroField.dict.set(PDFName.of("V"), PDFString.of("Not an /XFA form"));

  const body = await document.save({ useObjectStreams: false });

  assert.ok(
    Buffer.from(body).toString("latin1").includes("/XFA"),
    "expected raw AcroForm PDF bytes to contain literal /XFA in field value",
  );

  const imported = await importPdfDocument({
    body,
    contentType: "application/pdf",
    filename: "standard-acroform.pdf",
  });

  assert.equal(imported.pureXfa, false);
  assert.equal(imported.pageCount, 1);
});

test("a standard AcroForm PDF with /XFA null imports cleanly", async () => {
  const document = await PDFDocument.create();
  document.addPage([612, 792]);

  const acroForm = document.context.obj({
    Fields: [],
    XFA: PDFNull,
  });
  document.catalog.set(
    PDFName.of("AcroForm"),
    document.context.register(acroForm),
  );

  const body = await document.save({ useObjectStreams: false });
  const imported = await importPdfDocument({
    body,
    contentType: "application/pdf",
    filename: "null-xfa.pdf",
  });

  assert.equal(imported.pureXfa, false);
  assert.equal(imported.pageCount, 1);
});

test("a password-protected PDF is rejected as encrypted_pdf", async () => {
  const body = new Uint8Array(Buffer.from(PASSWORD_PDF_BASE64, "base64"));

  await assert.rejects(
    importPdfDocument({
      body,
      contentType: "application/pdf",
      filename: "locked.pdf",
    }),
    (error: unknown) =>
      error instanceof DocumentImportError &&
      error.code === "encrypted_pdf" &&
      error.message === getPdfImportErrorMessage("encrypted_pdf"),
  );
});

test("an owner-password-only encrypted PDF (empty user password) is rejected as encrypted_pdf", async () => {
  const body = buildOwnerPasswordOnlyPdf();

  // Confirm PDF.js can open it without a user password, proving it uses an
  // empty user password with owner restrictions rather than being unreadable.
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const task = pdfjs.getDocument({ data: body.slice(), verbosity: 0 });

  try {
    const pdfJsDoc = await task.promise;
    assert.equal(pdfJsDoc.numPages, 1);
    await pdfJsDoc.destroy();
  } finally {
    await task.destroy();
  }

  await assert.rejects(
    importPdfDocument({
      body,
      contentType: "application/pdf",
      filename: "owner-locked.pdf",
    }),
    (error: unknown) =>
      error instanceof DocumentImportError &&
      error.code === "encrypted_pdf" &&
      error.message === getPdfImportErrorMessage("encrypted_pdf"),
  );
});

test("PDFs with inline, xref-stream, or dangling trailer /Encrypt entries are rejected as encrypted_pdf", async () => {
  const inlineEncryptPdf = buildMinimalPdfWithTrailer(
    "/Encrypt << /Filter /Standard /V 1 /R 2 /Length 40 /P -44 /O <00> /U <00> >>",
  );
  const danglingEncryptPdf = buildMinimalPdfWithTrailer("/Encrypt 99 0 R");
  const xrefStreamEncryptPdf = buildXrefStreamEncryptedPdf();

  for (const [label, body] of [
    ["inline-encrypt.pdf", inlineEncryptPdf],
    ["dangling-encrypt.pdf", danglingEncryptPdf],
    ["xref-stream-encrypt.pdf", xrefStreamEncryptPdf],
  ] as const) {
    await assert.rejects(
      importPdfDocument({
        body,
        contentType: "application/pdf",
        filename: label,
      }),
      (error: unknown) =>
        error instanceof DocumentImportError &&
        error.code === "encrypted_pdf" &&
        error.message === getPdfImportErrorMessage("encrypted_pdf"),
      `expected ${label} to be rejected as encrypted_pdf`,
    );
  }
});

test("a PDF with Catalog -> AcroForm -> /XFA stream is rejected as unsupported_variant", async () => {
  const document = await PDFDocument.create();
  document.addPage([612, 792]);

  const xfaStream = document.context.flateStream(
    "<xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'></xdp:xdp>",
  );
  const xfaRef = document.context.register(xfaStream);
  const acroForm = document.context.obj({
    Fields: [],
    XFA: xfaRef,
  });
  document.catalog.set(
    PDFName.of("AcroForm"),
    document.context.register(acroForm),
  );

  const body = await document.save({ useObjectStreams: false });

  await assert.rejects(
    importPdfDocument({
      body,
      contentType: "application/pdf",
      filename: "xfa-stream.pdf",
    }),
    (error: unknown) =>
      error instanceof DocumentImportError &&
      error.code === "unsupported_variant" &&
      error.message === getPdfImportErrorMessage("unsupported_variant"),
  );
});

test("a PDF with Catalog -> AcroForm -> /XFA array or dictionary is rejected as unsupported_variant, including inside object streams", async () => {
  const makeXfaArrayPdf = async (useObjectStreams: boolean) => {
    const document = await PDFDocument.create();
    document.addPage([612, 792]);

    const templateStream = document.context.flateStream("<template/>");
    const templateRef = document.context.register(templateStream);
    const acroForm = document.context.obj({
      Fields: [],
      XFA: [PDFString.of("template"), templateRef],
    });
    document.catalog.set(
      PDFName.of("AcroForm"),
      document.context.register(acroForm),
    );

    return document.save({ useObjectStreams });
  };

  const xfaArrayPlain = await makeXfaArrayPdf(false);
  const xfaArrayCompressed = await makeXfaArrayPdf(true);

  assert.equal(
    Buffer.from(xfaArrayCompressed).toString("latin1").includes("/XFA"),
    false,
    "expected compressed object stream PDF to hide literal /XFA from raw bytes",
  );

  const dictDoc = await PDFDocument.create();
  dictDoc.addPage([612, 792]);
  const inlineAcroForm = dictDoc.context.obj({
    Fields: [],
    XFA: dictDoc.context.obj({ Template: PDFString.of("inline") }),
  });
  dictDoc.catalog.set(PDFName.of("AcroForm"), inlineAcroForm);
  const xfaInlineDict = await dictDoc.save({ useObjectStreams: false });

  for (const [label, body] of [
    ["xfa-array.pdf", xfaArrayPlain],
    ["xfa-compressed-objstm.pdf", xfaArrayCompressed],
    ["xfa-inline-dict.pdf", xfaInlineDict],
  ] as const) {
    await assert.rejects(
      importPdfDocument({
        body,
        contentType: "application/pdf",
        filename: label,
      }),
      (error: unknown) =>
        error instanceof DocumentImportError &&
        error.code === "unsupported_variant" &&
        error.message === getPdfImportErrorMessage("unsupported_variant"),
      `expected ${label} to be rejected as unsupported_variant`,
    );
  }
});

test("corrupt bytes with a PDF header are rejected as unreadable_pdf", async () => {
  await assert.rejects(
    importPdfDocument({
      body: new TextEncoder().encode("%PDF-1.7\nnot valid pdf objects"),
      contentType: "application/pdf",
      filename: "corrupt.pdf",
    }),
    (error: unknown) =>
      error instanceof DocumentImportError && error.code === "unreadable_pdf",
  );
});
