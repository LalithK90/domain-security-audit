"""
PDF Report Generator
====================
Generates professional PDF reports from domain security scan results
"""

from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime
from typing import Dict, List, Optional, Any
import io


class PDFReportGenerator:
    """Generate professional PDF reports from scan results"""
    
    def __init__(self, filename: str = None):
        """Initialize PDF generator"""
        self.filename = filename or f"domain_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        self.styles = getSampleStyleSheet()
        self._define_custom_styles()
    
    def _define_custom_styles(self):
        """Define custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#ffffff'),
            spaceAfter=6,
            spaceBefore=0,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            backColor=colors.HexColor('#2c3e50'),
            leftIndent=0,
            rightIndent=0,
            topPadding=8,
            bottomPadding=8,
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHead',
            parent=self.styles['Heading2'],
            fontSize=12,
            textColor=colors.HexColor('#ffffff'),
            spaceAfter=4,
            spaceBefore=8,
            fontName='Helvetica-Bold',
            backColor=colors.HexColor('#34495e'),
            leftIndent=6,
            rightIndent=6,
            topPadding=4,
            bottomPadding=4,
        ))
        
        self.styles.add(ParagraphStyle(
            name='BodyCompact',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceAfter=2,
            spaceBefore=0,
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['BodyCompact'],
            textColor=colors.HexColor('#e74c3c'),
            fontSize=9,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['BodyCompact'],
            textColor=colors.HexColor('#f39c12'),
            fontSize=9,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Success',
            parent=self.styles['BodyCompact'],
            textColor=colors.HexColor('#27ae60'),
            fontSize=9,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, scan_results: Dict, output_file: Optional[str] = None) -> str:
        """
        Generate complete PDF report from scan results
        
        Args:
            scan_results: Dictionary containing complete scan results
            output_file: Optional custom output filename
        
        Returns:
            Path to generated PDF file
        """
        output_path = output_file or self.filename
        
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.45*inch,
            leftMargin=0.45*inch,
            topMargin=0.4*inch,
            bottomMargin=0.35*inch
        )
        
        # Build document elements
        story = []
        
        # Title with background
        story.append(Paragraph("Domain Security Audit Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 0.02*inch))
        
        # Executive Summary
        domain = scan_results.get('domain', 'Unknown')
        scan_date = scan_results.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        duration = scan_results.get('duration', 'N/A')
        total_targets = scan_results.get('total_targets', 'N/A')
        
        summary_data = [
            ['Domain:', domain, 'Scan ID:', scan_results.get('scan_id', 'N/A')],
            ['Date:', scan_date, 'Duration:', f"{duration}s" if isinstance(duration, (int, float)) else str(duration)],
            ['Targets:', str(total_targets), '', ''],
        ]
        
        summary_table = Table(summary_data, colWidths=[1.2*inch, 2*inch, 1.2*inch, 1.8*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.02*inch))
        
        def add_page_number(canvas_obj, doc_obj):
            canvas_obj.saveState()
            canvas_obj.setFont("Helvetica", 8)
            canvas_obj.setFillColor(colors.HexColor('#7f8c8d'))
            canvas_obj.drawRightString(
                doc_obj.pagesize[0] - doc_obj.rightMargin,
                0.25 * inch,
                f"Page {canvas_obj.getPageNumber()}"
            )
            canvas_obj.restoreState()

        def add_section(title: str, elements: List):
            block = [Paragraph(title, self.styles['SectionHead'])] + elements
            story.append(KeepTogether(block))
            story.append(Spacer(1, 0.01*inch))

        # Add sections
        add_section("1. Enumeration Results", self._build_enumeration_section(scan_results.get('enumeration', {})))
        add_section("2. Security Assessment", self._build_security_section(scan_results.get('security_checks', {})))

        risk_data = scan_results.get('risk_assessment', {})
        if risk_data:
            add_section("3. Risk Assessment", self._build_risk_section(risk_data))

        add_section("4. Email Security", self._build_email_section(scan_results.get('email_security', {})))
        add_section("5. Takeover Vulnerabilities", self._build_takeover_section(scan_results.get('takeover', {})))

        error_data = scan_results.get('errors', {})
        if error_data:
            add_section("6. Scan Errors Summary", self._build_error_section(error_data))

        add_section("7. Recommendations", self._build_recommendations_section(scan_results.get('recommendations', [])))

        # Build PDF with page numbers
        doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
        
        return output_path
    
    
    def _build_enumeration_section(self, enum_data: Dict) -> List:
        """Build enumeration results section"""
        elements = []
        
        subdomains = enum_data.get('subdomains', [])
        methods = enum_data.get('methods_used', [])
        subdomain_details = enum_data.get('subdomain_details', [])
        
        # Summary statistics - compact
        summary = f"<b>Total Subdomains:</b> {len(subdomains)} | <b>Methods:</b> {len(methods)} | <b>Details:</b> {', '.join(methods) if methods else 'N/A'}"
        elements.append(Paragraph(summary, self.styles['BodyCompact']))
        elements.append(Spacer(1, 0.02*inch))
        
        # Method distribution chart if available
        method_counts = enum_data.get('method_counts', {})
        if method_counts and len(subdomains) > 0:
            elements.append(self._create_method_chart(method_counts))
            elements.append(Spacer(1, 0.02*inch))
        
        # Subdomain details table - more compact
        if subdomain_details and len(subdomain_details) > 0:
            elements.append(Paragraph("<b>Discovered Subdomains (Top 15)</b>", self.styles['BodyCompact']))
            elements.append(Spacer(1, 0.01*inch))
            
            table_data = [['#', 'Subdomain', 'IP', 'Method']]
            for i, sub in enumerate(subdomain_details[:15], 1):
                fqdn = sub.get('fqdn', 'N/A')
                ip = sub.get('ip', 'N/A')[:15] if sub.get('ip') else 'N/A'
                method = sub.get('method', 'N/A')[:10] if sub.get('method') else 'N/A'
                table_data.append([str(i), fqdn, ip, method])
            
            table = Table(table_data, colWidths=[0.35*inch, 2.5*inch, 1.3*inch, 0.9*inch])
            table.setStyle(self._get_compact_table_style())
            elements.append(table)
            
            if len(subdomain_details) > 15:
                elements.append(Spacer(1, 0.01*inch))
                elements.append(Paragraph(
                    f"<i>... and {len(subdomain_details) - 15} more subdomains</i>",
                    self.styles['BodyCompact']
                ))
        elif subdomains:
            elements.append(Paragraph("<b>Discovered Subdomains</b>", self.styles['BodyCompact']))
            elements.append(Spacer(1, 0.01*inch))
            
            table_data = [['#', 'Subdomain']]
            for i, sub in enumerate(subdomains[:12], 1):
                sub_str = str(sub) if not isinstance(sub, dict) else sub.get('fqdn', str(sub))
                table_data.append([str(i), sub_str])
            
            table = Table(table_data, colWidths=[0.4*inch, 5*inch])
            table.setStyle(self._get_compact_table_style())
            elements.append(table)
        
        return elements
    
    def _build_security_section(self, security_data: Dict) -> List:
        """Build security checks section"""
        elements = []
        
        passed = security_data.get('passed', 0)
        failed = security_data.get('failed', 0)
        total = passed + failed
        
        if total > 0:
            pass_rate = (passed / total) * 100
            
            # Add pie chart
            elements.append(self._create_security_pie_chart(passed, failed))
            elements.append(Spacer(1, 0.02*inch))
            
            # Summary stats inline
            stats = f"<b>Passed:</b> {passed} ({pass_rate:.0f}%) | <b>Failed:</b> {failed} ({100-pass_rate:.0f}%) | <b>Total:</b> {total}"
            elements.append(Paragraph(stats, self.styles['BodyCompact']))
            elements.append(Spacer(1, 0.02*inch))
        else:
            elements.append(Paragraph("No security check data available", self.styles['BodyCompact']))
            return elements
        
        # Detailed findings table - compact
        findings = security_data.get('findings', [])
        if findings:
            elements.append(Paragraph("<b>Security Findings</b>", self.styles['BodyCompact']))
            elements.append(Spacer(1, 0.01*inch))
            
            table_data = [['Check', 'Status', 'Count', 'Severity']]
            for finding in findings[:12]:
                check = str(finding.get('check', 'N/A'))[:20]
                status = finding.get('status', 'N/A')
                count = finding.get('count', 0)
                severity = finding.get('severity', 'N/A')
                
                # Use simple text indicators (HTML tags don't render in table cells)
                if status.lower() == 'pass':
                    status_text = 'Pass'
                elif status.lower() == 'fail':
                    status_text = 'Fail'
                else:
                    status_text = status[:4]
                
                table_data.append([check, status_text, str(count), severity[:4]])
            
            table = Table(table_data, colWidths=[1.8*inch, 0.4*inch, 0.5*inch, 0.7*inch])
            table.setStyle(self._get_compact_table_style())
            elements.append(table)
        
        return elements
    
    def _build_email_section(self, email_data: Dict) -> List:
        """Build email security section"""
        elements = []
        
        if not email_data:
            elements.append(Paragraph("No email security data available", self.styles['BodyCompact']))
            return elements
        
        spf = email_data.get('spf', {})
        dmarc = email_data.get('dmarc', {})
        dkim = email_data.get('dkim', {})
        
        # SPF Status - inline
        spf_status = "✓ Configured" if spf.get('has_spf') else "✗ Missing"
        dmarc_status = f"✓ {dmarc.get('policy', 'unknown')}" if dmarc.get('has_dmarc') else "✗ Missing"
        dkim_count = sum(1 for v in dkim.values() if v) if dkim else 0
        dkim_status = f"✓ {dkim_count} selectors" if dkim_count > 0 else "✗ None"
        
        summary = f"<b>SPF:</b> {spf_status} | <b>DMARC:</b> {dmarc_status} | <b>DKIM:</b> {dkim_status}"
        elements.append(Paragraph(summary, self.styles['BodyCompact']))
        
        return elements
    
    def _build_takeover_section(self, takeover_data: Dict) -> List:
        """Build takeover vulnerabilities section"""
        elements = []
        
        critical = takeover_data.get('critical', 0)
        high = takeover_data.get('high', 0)
        
        if critical > 0:
            elements.append(Paragraph(
                f"<font color=red><b>⚠ {critical} CRITICAL takeover found</b></font>",
                self.styles['BodyCompact']
            ))
        elif high > 0:
            elements.append(Paragraph(
                f"<font color=orange><b>⚠ {high} HIGH risk found</b></font>",
                self.styles['BodyCompact']
            ))
        else:
            elements.append(Paragraph(
                "<font color=green>✓ No critical takeover vulnerabilities</font>",
                self.styles['BodyCompact']
            ))
        
        return elements
    
    def _build_recommendations_section(self, recommendations: List[str]) -> List:
        """Build recommendations section"""
        elements = []
        
        if not recommendations:
            elements.append(Paragraph("No specific recommendations at this time", self.styles['BodyCompact']))
            return elements
        
        for i, rec in enumerate(recommendations[:10], 1):
            elements.append(Paragraph(
                f"{i}. {rec}",
                self.styles['BodyCompact']
            ))
        
        return elements
    
    def _get_table_style(self) -> TableStyle:
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('TOPPADDING', (0, 0), (-1, 0), 3),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 3),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9f9')]),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('TOPPADDING', (0, 1), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 2),
        ])
    
    def _get_compact_table_style(self) -> TableStyle:
        """Get compact table style for dense tables"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 2),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 2),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('FONTSIZE', (0, 1), (-1, -1), 7.5),
            ('TOPPADDING', (0, 1), (-1, -1), 1),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 1),
        ])
    
    def _create_security_pie_chart(self, passed: int, failed: int) -> Drawing:
        """Create a compact pie chart showing security check results"""
        drawing = Drawing(300, 140)
        pie = Pie()
        pie.x = 80
        pie.y = 20
        pie.width = 100
        pie.height = 100
        pie.data = [passed, failed]
        pie.labels = [f'P:{passed}', f'F:{failed}']
        pie.slices[0].fillColor = colors.HexColor('#27ae60')
        pie.slices[1].fillColor = colors.HexColor('#e74c3c')
        pie.slices.strokeWidth = 0.3
        drawing.add(pie)
        return drawing
    
    def _create_method_chart(self, method_counts: Dict[str, int]) -> Drawing:
        """Create a compact bar chart showing enumeration method distribution"""
        drawing = Drawing(400, 120)
        bc = VerticalBarChart()
        bc.x = 30
        bc.y = 15
        bc.height = 80
        bc.width = 350
        
        methods = list(method_counts.keys())[:6]  # Top 6 methods only
        counts = [method_counts[m] for m in methods]
        
        bc.data = [counts]
        bc.categoryAxis.categoryNames = [m[:8] if len(m) > 8 else m for m in methods]
        bc.categoryAxis.labels.angle = 45
        bc.categoryAxis.labels.dx = -2
        bc.categoryAxis.labels.dy = -2
        bc.categoryAxis.labels.fontSize = 6
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = max(counts) * 1.1 if counts else 10
        bc.valueAxis.labels.fontSize = 6
        bc.bars[0].fillColor = colors.HexColor('#3498db')
        
        drawing.add(bc)
        return drawing
    
    def _build_risk_section(self, risk_data: Dict[str, int]) -> List:
        """Build risk assessment section"""
        elements = []
        
        if not risk_data:
            elements.append(Paragraph("No risk assessment data available", self.styles['BodyCompact']))
            return elements
        
        # Risk distribution table - compact
        table_data = [['Risk', 'Count', '%']]
        total = sum(risk_data.values())
        
        # Sort by severity
        risk_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        for risk in risk_order:
            if risk in risk_data:
                count = risk_data[risk]
                pct = (count / total * 100) if total > 0 else 0
                
                # Use clean text labels (HTML tags don't render in table cells)
                risk_text = risk
                table_data.append([risk_text, str(count), f'{pct:.0f}%'])
        
        # Add any other risk levels not in standard order
        for risk, count in risk_data.items():
            if risk not in risk_order:
                pct = (count / total * 100) if total > 0 else 0
                table_data.append([str(risk), str(count), f'{pct:.0f}%'])
        
        table = Table(table_data, colWidths=[1.5*inch, 0.7*inch, 0.6*inch])
        table.setStyle(self._get_compact_table_style())
        elements.append(table)
        
        return elements
    
    def _build_error_section(self, error_data: Dict[str, int]) -> List:
        """Build error summary section"""
        elements = []
        
        if not error_data:
            elements.append(Paragraph("<font color=green>✓ No errors</font>", self.styles['BodyCompact']))
            return elements
        
        total_errors = sum(error_data.values())
        elements.append(Paragraph(
            f"<b>Total Errors: {total_errors}</b>",
            self.styles['BodyCompact']
        ))
        elements.append(Spacer(1, 0.01*inch))
        
        # Error breakdown table - compact
        table_data = [['Reason', 'Count', '%']]
        for reason, count in list(error_data.items())[:5]:
            pct = (count / total_errors * 100) if total_errors > 0 else 0
            reason_short = str(reason)[:20]
            table_data.append([reason_short, str(count), f'{pct:.0f}%'])
        
        table = Table(table_data, colWidths=[2.3*inch, 0.6*inch, 0.6*inch])
        table.setStyle(self._get_compact_table_style())
        elements.append(table)
        
        return elements
    
    def _build_recommendations_section(self, recommendations: List[str]) -> List:
        """Build recommendations section"""
        elements = []
        
        if not recommendations:
            elements.append(Paragraph("No specific recommendations at this time", self.styles['BodyCompact']))
            return elements
        
        for i, rec in enumerate(recommendations[:7], 1):
            # Shorten recommendations if too long
            rec_short = str(rec)[:110]
            elements.append(Paragraph(
                f"<b>{i}.</b> {rec_short}{'...' if len(str(rec)) > 110 else ''}",
                self.styles['BodyCompact']
            ))
        
        return elements
