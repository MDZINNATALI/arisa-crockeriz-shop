from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import os
from models import Invoice, db
from datetime import datetime

def generate_invoice(order):
    """অর্ডারের জন্য ইনভয়েস জেনারেট করে"""
    
    # ইনভয়েস ফোল্ডার চেক করুন
    invoice_folder = 'static/invoices'
    if not os.path.exists(invoice_folder):
        os.makedirs(invoice_folder)
    
    filename = f"invoice_{order.order_number}.pdf"
    filepath = os.path.join(invoice_folder, filename)
    
    # PDF ডকুমেন্ট তৈরি
    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # শিরোনাম
    title = Paragraph(f"ইনভয়েস #{order.order_number}", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 0.2*inch))
    
    # তারিখ
    date_str = order.created_at.strftime('%d %B, %Y')
    date_para = Paragraph(f"তারিখ: {date_str}", styles['Normal'])
    story.append(date_para)
    story.append(Spacer(1, 0.2*inch))
    
    # গ্রাহকের তথ্য
    customer_info = f"""
    <b>গ্রাহক:</b> {order.customer.username}<br/>
    <b>ইমেইল:</b> {order.customer.email}<br/>
    <b>ফোন:</b> {order.phone}<br/>
    <b>ঠিকানা:</b> {order.shipping_address}
    """
    story.append(Paragraph(customer_info, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # অর্ডার আইটেম টেবিল
    data = [['প্রোডাক্ট', 'দাম', 'পরিমাণ', 'মোট']]
    for item in order.items:
        data.append([item.product_name, f"৳{item.price}", str(item.quantity), f"৳{item.total}"])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('GRID', (0,0), (-1,-2), 1, colors.black)
    ]))
    
    story.append(table)
    story.append(Spacer(1, 0.2*inch))
    
    # সারাংশ
    summary_data = [
        ['সাবটোটাল:', f"৳{order.total_amount}"],
        ['ছাড়:', f"৳{order.discount_amount}"],
        ['সর্বমোট:', f"৳{order.final_amount}"]
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (0,-1), 'RIGHT'),
        ('ALIGN', (1,0), (1,-1), 'RIGHT'),
        ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    
    story.append(summary_table)
    
    # PDF বিল্ড
    doc.build(story)
    
    # ডাটাবেসে ইনভয়েস সংরক্ষণ
    invoice = Invoice(
        order_id=order.id,
        invoice_number=f"INV-{order.order_number}",
        pdf_path=filename
    )
    db.session.add(invoice)
    db.session.commit()
    
    return filepath