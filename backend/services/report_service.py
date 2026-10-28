"""
Report Export Service: Formatted JSON and PDF security report generation.
"""
import io
import json
import html
from typing import Dict, Any
from backend.models import Scan


def build_scan_json_export(scan: Scan) -> Dict[str, Any]:
    """Generates complete, structured JSON export of the scan."""
    findings_data = [
        {
            "id": f.finding_id,
            "group": f.group,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "title": f.title,
            "detail": f.detail,
            "evidence": f.evidence or []
        }
        for f in scan.findings
    ]
    feedback_data = [
        {
            "user_id": fb.user_id,
            "verdict": fb.verdict,
            "notes": fb.notes,
            "created_at": fb.created_at.isoformat()
        }
        for fb in scan.feedback
    ]

    return {
        "report_type": "URL Threat Detonation Analysis",
        "platform": "Cloud XDR URL Analyzer",
        "scan_id": scan.id,
        "submitted_url": scan.url,
        "normalized_domain": scan.normalized_domain,
        "status": scan.status,
        "created_at": scan.created_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "verdict": {
            "threat_score": scan.threat_score,
            "threat_level": scan.threat_level,
            "hygiene_score": scan.hygiene_score,
            "hygiene_level": scan.hygiene_level,
            "summary": scan.summary,
        },
        "findings_count": len(findings_data),
        "findings": findings_data,
        "analyst_feedback": feedback_data,
        "evidence": scan.evidence or {},
    }


def generate_scan_pdf_report(scan: Scan) -> bytes:
    """
    Generates a clean, valid PDF binary report.
    Tries reportlab if installed; otherwise produces a valid formatted PDF.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#121826'),
            spaceAfter=12
        )
        elements.append(Paragraph("<b>URL Threat Analysis Report</b>", title_style))
        elements.append(Paragraph(f"<b>Target URL:</b> {html.escape(scan.url)}", styles['Normal']))
        elements.append(Paragraph(f"<b>Domain:</b> {html.escape(scan.normalized_domain)} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Scan ID:</b> {scan.id}", styles['Normal']))
        elements.append(Paragraph(f"<b>Generated (UTC):</b> {scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 14))

        # Metrics Table
        sev_color = colors.HexColor('#ff4d6d') if scan.threat_level == 'Critical' else colors.HexColor('#ff8a3d') if scan.threat_level == 'High' else colors.HexColor('#f5c542') if scan.threat_level == 'Medium' else colors.HexColor('#4dd4ac')
        metrics_data = [
            ["Threat Score", f"{scan.threat_score}/100 ({scan.threat_level})", "Hygiene Score", f"{scan.hygiene_score}/100 ({scan.hygiene_level})"],
        ]
        t = Table(metrics_data, colWidths=[110, 150, 110, 150])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f4f6f8')),
            ('TEXTCOLOR', (1, 0), (1, 0), sev_color),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d0d7de')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 14))

        # Summary
        elements.append(Paragraph("<b>Executive Summary</b>", styles['Heading3']))
        elements.append(Paragraph(html.escape(scan.summary), styles['Normal']))
        elements.append(Spacer(1, 14))

        # Findings
        elements.append(Paragraph(f"<b>Observed Findings ({len(scan.findings)})</b>", styles['Heading3']))
        if not scan.findings:
            elements.append(Paragraph("No hostile or security hygiene findings were recorded.", styles['Normal']))
        else:
            findings_table_data = [["Severity", "Title", "Category", "Confidence"]]
            for f in scan.findings:
                findings_table_data.append([
                    f.severity.upper(),
                    Paragraph(html.escape(f.title), styles['Normal']),
                    f.category,
                    f"{int(f.confidence * 100)}%"
                ])
            ftable = Table(findings_table_data, colWidths=[70, 280, 100, 70])
            ftable.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#121826')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7de')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(ftable)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    except Exception:
        # Self-contained minimal PDF writer fallback
        return _build_raw_pdf(scan)


def _build_raw_pdf(scan: Scan) -> bytes:
    """Pure Python minimal valid PDF-1.4 file output."""
    safe_url = html.escape(scan.url).encode('latin-1', 'replace').decode('latin-1')
    safe_summary = html.escape(scan.summary).encode('latin-1', 'replace').decode('latin-1')
    
    stream_content = f"""BT
/F1 16 Tf
50 750 Td
(Cloud XDR URL Threat Analysis Report) Tj
/F1 11 Tf
0 -24 Td
(Scan ID: {scan.id}) Tj
0 -18 Td
(URL: {safe_url[:80]}) Tj
0 -18 Td
(Domain: {scan.normalized_domain}) Tj
0 -18 Td
(Threat Score: {scan.threat_score}/100 [{scan.threat_level}]) Tj
0 -18 Td
(Hygiene Score: {scan.hygiene_score}/100 [{scan.hygiene_level}]) Tj
0 -26 Td
(Summary:) Tj
0 -16 Td
({safe_summary[:100]}) Tj
0 -30 Td
(Findings Recorded: {len(scan.findings)}) Tj
ET"""
    
    stream_bytes = stream_content.encode("latin-1")
    length = len(stream_bytes)
    
    pdf = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {length} >>
stream
{stream_content}
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000000 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
400
%%EOF"""
    return pdf.encode("latin-1")
