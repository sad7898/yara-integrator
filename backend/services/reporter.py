import io
import json
from typing import IO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT
from textwrap import wrap
import PyPDF2
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle

class Reporter:
    def __init__(self,tableStyle=None):
        if tableStyle is None:
            self.tableStyle = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("BOX", (0, 0), (-1, -1), 1, colors.black),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.black),
        ])
        else:
            self.tableStyle = tableStyle
            
    def listToTable(self,data: list,headers:list):
        table_data = [headers] + data 
        # Create the table object
        table = Table(table_data,hAlign='LEFT')
        table.setStyle(self.tableStyle)
        return table
    
    def buildPdf(self,contents) -> IO:
        pdfBytes = io.BytesIO()
        pdf = SimpleDocTemplate(pdfBytes, pagesize=letter,rightMargin = 20, leftMargin = 20, topMargin = 20, bottomMargin = 28)

        titleStyle = ParagraphStyle(name="heading",fontSize=20,alignment=TA_LEFT)
        title = Paragraph("YARA rules", titleStyle)
        pdf.build([title,Spacer(1, 0.25*inch)] + contents)
        pdfBytes.seek(0)
        return pdfBytes

    def appendBytesToPDF(self,existingPDF: IO,newPDF:IO):
        writer = PyPDF2.PdfMerger()
        writer.append(existingPDF)
        writer.append(fileobj=newPDF)
        output = io.BytesIO()
        writer.write(output)
        output.seek(0)
        return output
    
    
    def report(self,yaraResults: dict):
        headers = ["Namespace","Rules Matched","Description"]
        rows = []
        for namespace in yaraResults:
            wrappedDesc = "\n".join(wrap(yaraResults[namespace]['description'],0.75 * inch))
            rows.append([namespace,",".join(yaraResults[namespace]['rules']),wrappedDesc])
        table = self.listToTable(rows,headers)
        pdf = self.buildPdf([table])
        return pdf
                    

