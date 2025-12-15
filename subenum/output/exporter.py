import json
import csv
from pathlib import Path

class ResultExporter:
    """
    Exports scan results to various formats (JSON, CSV, TXT).
    """
    
    def export(self, findings: list, output_file: str, format: str):
        """
        Export findings to file in specified format.
        """
        if format == 'json':
            self._export_json(findings, output_file)
        elif format == 'csv':
            self._export_csv(findings, output_file)
        elif format == 'txt':
            self._export_txt(findings, output_file)
    
    def _export_json(self, findings: list, output_file: str):
        """Export as JSON with full metadata."""
        data = []
        for finding in findings:
            data.append({
                'domain': finding.domain,
                'ip': finding.ip,
                'status': finding.status,
                'rtype': finding.rtype,
                'cname': finding.cname,
                'provider': finding.provider,
                'http_status': finding.http_status,
                'waf': finding.waf,
                'title': finding.title,
                'content_length': finding.content_length,
                'location': finding.location,
                'score': finding.score,
                'risk_reasons': finding.risk_reasons,
                'is_takeover': finding.is_takeover,
                'takeover_service': finding.takeover_service
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _export_csv(self, findings: list, output_file: str):
        """Export as CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Header
            writer.writerow(['Domain', 'IP', 'Status', 'Type', 'CNAME', 'Provider', 
                           'HTTP Status', 'WAF', 'Title', 'Content Length', 'Location',
                           'Risk Score', 'Risk Reasons', 'Takeover', 'Takeover Service'])
            
            # Data
            for finding in findings:
                writer.writerow([
                    finding.domain,
                    finding.ip,
                    finding.status,
                    finding.rtype,
                    finding.cname,
                    finding.provider,
                    finding.http_status,
                    finding.waf,
                    finding.title,
                    finding.content_length,
                    finding.location,
                    finding.score,
                    ', '.join(finding.risk_reasons) if finding.risk_reasons else '',
                    finding.is_takeover,
                    finding.takeover_service
                ])
    
    def _export_txt(self, findings: list, output_file: str):
        """Export as plain text (domain list)."""
        with open(output_file, 'w', encoding='utf-8') as f:
            for finding in findings:
                f.write(f"{finding.domain}\n")
