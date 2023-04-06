import io
import json
from typing import IO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import PyPDF2
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

class Reporter:
    def __init__(self,tableStyle=None):
        if tableStyle is None:
            self.tableStyle = TableStyle([('ALIGN',(1,1),(-2,-2),'RIGHT'),
                       ('TEXTCOLOR',(1,1),(-2,-2),colors.red),
                       ('VALIGN',(0,0),(0,-1),'TOP'),
                       ('TEXTCOLOR',(0,0),(0,-1),colors.blue),
                       ('ALIGN',(0,-1),(-1,-1),'CENTER'),
                       ('VALIGN',(0,-1),(-1,-1),'MIDDLE'),
                       ('TEXTCOLOR',(0,-1),(-1,-1),colors.green),
                       ('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),
                       ('BOX', (0,0), (-1,-1), 0.25, colors.black),
                       ])
        else:
            self.tableStyle = tableStyle
            
    def listToTable(self,data: list,headers:list):
        table_data = [headers] + [data]
        table = Table(table_data)
        table.setStyle(self.tableStyle)
        return table
    
    def buildTablesToPDF(self,table) -> IO:
        pdfBytes = io.BytesIO()
        pdf = SimpleDocTemplate(pdfBytes, pagesize=letter,rightMargin = 40, leftMargin = 40, topMargin = 40, bottomMargin = 28)
        pdf.build([table])
        pdfBytes.seek(0)
        return pdfBytes

    def appendBytesToPDF(self,bytes: IO,pdf: IO):
        existing_pdf = PyPDF2.PdfFileWriter(stream=pdf)
        new_page = PyPDF2.PdfFileReader(bytes).getPage(0)
        existing_pdf.addPage(new_page)
        return existing_pdf
    
    def report(self,yaraResults: dict,mobSfResults=None):
        table = self.listToTable([(namespace,yaraResults[namespace][0]) for namespace in yaraResults],["Namespace","Rules Matched"])
        pdf = self.buildTablesToPDF(table)
        if (mobSfResults is None):
            return pdf
        else:
            return pdf
                    

