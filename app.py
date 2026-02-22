from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Product, Cart, Order, OrderItem, Review, Coupon, Invoice
from datetime import datetime, timedelta
import os
import random
import string
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import time
import json
import tempfile

app = Flask(__name__)

# কনফিগারেশন
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-this')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Vercel এনভায়রনমেন্ট চেক
is_vercel = os.environ.get('VERCEL_ENV') is not None

# SQLAlchemy URI - Vercel চেক অনুযায়ী
if is_vercel:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/shop.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'

# এক্সটেনশন ইনিশিয়ালাইজ
db = SQLAlchemy()
db.init_app(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'অর্ডার করতে লগইন করুন'

# OTP স্টোরেজ (প্রোডাকশনে Redis ব্যবহার করবেন)
otp_storage = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# হেল্পার ফাংশন
def generate_order_number():
    return 'ORD' + ''.join(random.choices(string.digits, k=8))

def generate_invoice_number():
    return 'INV' + ''.join(random.choices(string.digits, k=8))

def generate_otp():
    return str(random.randint(100000, 999999))

def save_uploaded_file(file):
    """ফাইল সেভ করার হেল্পার ফাংশন"""
    filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filename

@app.context_processor
def cart_count():
    if current_user.is_authenticated:
        count = Cart.query.filter_by(user_id=current_user.id).count()
        total = sum(item.product.price * item.quantity for item in current_user.cart_items)
        return {'cart_count': count, 'cart_total': total}
    return {'cart_count': 0, 'cart_total': 0}

# ========== হোম পেজ ==========
@app.route('/')
def index():
    featured_products = Product.query.filter_by(featured=True).limit(8).all()
    new_products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    return render_template('index.html', 
                         featured_products=featured_products,
                         new_products=new_products)

# ========== প্রোডাক্ট ==========
@app.route('/products')
def products():
    category = request.args.get('category', 'all')
    search = request.args.get('search', '')
    
    query = Product.query
    if category != 'all':
        query = query.filter_by(category=category)
    if search:
        query = query.filter(Product.name.contains(search) | 
                           Product.description.contains(search))
    
    products = query.order_by(Product.created_at.desc()).all()
    categories = db.session.query(Product.category).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    
    return render_template('products.html', 
                         products=products, 
                         categories=categories,
                         current_category=category)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    related = Product.query.filter_by(category=product.category).filter(Product.id != id).limit(4).all()
    reviews = Review.query.filter_by(product_id=id).order_by(Review.created_at.desc()).all()
    return render_template('product_detail.html', product=product, related=related, reviews=reviews)

# ========== রিভিউ সিস্টেম ==========
@app.route('/product/<int:id>/review', methods=['POST'])
@login_required
def add_review(id):
    product = Product.query.get_or_404(id)
    
    rating = int(request.form['rating'])
    comment = request.form['comment']
    
    existing_review = Review.query.filter_by(user_id=current_user.id, product_id=id).first()
    if existing_review:
        flash('আপনি ইতিমধ্যে এই প্রোডাক্টে রিভিউ দিয়েছেন')
        return redirect(url_for('product_detail', id=id))
    
    review = Review(
        user_id=current_user.id,
        product_id=id,
        rating=rating,
        comment=comment
    )
    
    db.session.add(review)
    db.session.commit()
    
    flash('রিভিউ যোগ হয়েছে! ধন্যবাদ')
    return redirect(url_for('product_detail', id=id))

# ========== ইউজার রেজিস্ট্রেশন ==========
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        
        if User.query.filter_by(username=username).first():
            flash('এই ইউজারনেম ইতিমধ্যে আছে')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('এই ইমেইল ইতিমধ্যে আছে')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(
            username=username, 
            email=email, 
            password_hash=hashed_password, 
            phone=phone,
            phone_verified=False,
            email_verified=False,
            two_factor_enabled=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('রেজিস্ট্রেশন সফল! এখন লগইন করুন')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ========== লগইন ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if user.two_factor_enabled:
                otp = generate_otp()
                otp_storage[user.id] = {
                    'otp': otp,
                    'time': time.time()
                }
                print(f"2FA code for {user.email}: {otp}")
                
                session['2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            else:
                login_user(user)
                flash(f'স্বাগতম {user.username}!')
                return redirect(url_for('index'))
        else:
            flash('ভুল ইউজারনেম বা পাসওয়ার্ড')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        user_id = session.get('2fa_user_id')
        code = request.form['code']
        
        stored = otp_storage.get(user_id)
        if stored and stored['otp'] == code and (time.time() - stored['time']) < 300:
            user = User.query.get(user_id)
            login_user(user)
            session.pop('2fa_user_id', None)
            otp_storage.pop(user_id, None)
            flash('২-ফ্যাক্টর অথেনটিকেশন সফল!')
            return redirect(url_for('index'))
        else:
            flash('ভুল অথবা মেয়াদোত্তীর্ণ কোড')
    
    return render_template('verify_2fa.html')

# ========== লগআউট ==========
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('আপনি লগআউট করেছেন')
    return redirect(url_for('index'))

# ========== প্রোফাইল ও 2FA রুটসমূহ ==========
@app.route('/profile')
@login_required
def profile():
    """ইউজার প্রোফাইল দেখার জন্য"""
    return render_template('profile.html', user=current_user)

@app.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """২-ফ্যাক্টর অথেনটিকেশন চালু করুন"""
    current_user.two_factor_enabled = True
    db.session.commit()
    flash('✅ ২-ফ্যাক্টর অথেনটিকেশন সক্রিয় করা হয়েছে')
    return redirect(url_for('profile'))

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """২-ফ্যাক্টর অথেনটিকেশন বন্ধ করুন"""
    current_user.two_factor_enabled = False
    db.session.commit()
    flash('❌ ২-ফ্যাক্টর অথেনটিকেশন নিষ্ক্রিয় করা হয়েছে')
    return redirect(url_for('profile'))

@app.route('/verify-phone', methods=['POST'])
@login_required
def verify_phone():
    """ফোন নম্বর ভেরিফিকেশন OTP পাঠান"""
    if not current_user.phone:
        flash('প্রথমে ফোন নম্বর সেট করুন')
        return redirect(url_for('profile'))
    
    otp = str(random.randint(100000, 999999))
    otp_storage[f'phone_{current_user.id}'] = {
        'otp': otp,
        'time': time.time()
    }
    
    print(f"📱 ফোন ভেরিফিকেশন OTP for {current_user.phone}: {otp}")
    flash('ভেরিফিকেশন কোড পাঠানো হয়েছে (কনসোল চেক করুন)')
    return redirect(url_for('verify_phone_code'))

@app.route('/verify-phone-code', methods=['GET', 'POST'])
@login_required
def verify_phone_code():
    """ফোন ভেরিফিকেশন OTP চেক করুন"""
    if request.method == 'POST':
        code = request.form['code']
        stored = otp_storage.get(f'phone_{current_user.id}')
        
        if stored and stored['otp'] == code and (time.time() - stored['time']) < 300:
            current_user.phone_verified = True
            db.session.commit()
            otp_storage.pop(f'phone_{current_user.id}', None)
            flash('✅ ফোন নম্বর ভেরিফাই হয়েছে!')
            return redirect(url_for('profile'))
        else:
            flash('❌ ভুল অথবা মেয়াদোত্তীর্ণ কোড')
    
    return render_template('verify_phone.html')

@app.route('/verify-email', methods=['POST'])
@login_required
def verify_email():
    """ইমেইল ভেরিফিকেশন OTP পাঠান"""
    otp = str(random.randint(100000, 999999))
    otp_storage[f'email_{current_user.id}'] = {
        'otp': otp,
        'time': time.time()
    }
    
    print(f"📧 ইমেইল ভেরিফিকেশন OTP for {current_user.email}: {otp}")
    flash('ভেরিফিকেশন কোড ইমেইলে পাঠানো হয়েছে (কনসোল চেক করুন)')
    return redirect(url_for('verify_email_code'))

@app.route('/verify-email-code', methods=['GET', 'POST'])
@login_required
def verify_email_code():
    """ইমেইল ভেরিফিকেশন OTP চেক করুন"""
    if request.method == 'POST':
        code = request.form['code']
        stored = otp_storage.get(f'email_{current_user.id}')
        
        if stored and stored['otp'] == code and (time.time() - stored['time']) < 300:
            current_user.email_verified = True
            db.session.commit()
            otp_storage.pop(f'email_{current_user.id}', None)
            flash('✅ ইমেইল ভেরিফাই হয়েছে!')
            return redirect(url_for('profile'))
        else:
            flash('❌ ভুল অথবা মেয়াদোত্তীর্ণ কোড')
    
    return render_template('verify_email.html')

# ========== FAQ রুট ==========
@app.route('/faq')
def faq():
    """সচরাচর জিজ্ঞাসা পৃষ্ঠা"""
    return render_template('faq.html')

# ========== কার্ট সিস্টেম ==========
@app.route('/add-to-cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.stock < 1:
        flash('স্টকে নেই')
        return redirect(url_for('product_detail', id=product_id))
    
    cart_item = Cart.query.filter_by(user_id=current_user.id, 
                                    product_id=product_id).first()
    
    if cart_item:
        if cart_item.quantity < product.stock:
            cart_item.quantity += 1
            flash('প্রোডাক্টের পরিমাণ বাড়ানো হয়েছে')
        else:
            flash('স্টক শেষ')
    else:
        cart_item = Cart(user_id=current_user.id, product_id=product_id, quantity=1)
        db.session.add(cart_item)
        flash('প্রোডাক্ট কার্টে যোগ হয়েছে')
    
    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    subtotal = sum(item.product.price * item.quantity for item in cart_items)
    
    discount = session.get('discount', 0)
    total = subtotal - discount
    
    return render_template('cart.html', 
                         cart_items=cart_items, 
                         subtotal=subtotal,
                         discount=discount,
                         total=total)

@app.route('/update-cart/<int:item_id>', methods=['POST'])
@login_required
def update_cart(item_id):
    cart_item = Cart.query.get_or_404(item_id)
    quantity = int(request.form['quantity'])
    
    if quantity > 0 and quantity <= cart_item.product.stock:
        cart_item.quantity = quantity
        db.session.commit()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            subtotal = sum(item.product.price * item.quantity for item in current_user.cart_items)
            discount = session.get('discount', 0)
            total = subtotal - discount
            
            return jsonify({
                'success': True,
                'item_total': cart_item.product.price * quantity,
                'subtotal': subtotal,
                'discount': discount,
                'total': total
            })
    elif quantity == 0:
        db.session.delete(cart_item)
        db.session.commit()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            subtotal = sum(item.product.price * item.quantity for item in current_user.cart_items)
            discount = session.get('discount', 0)
            total = subtotal - discount
            
            return jsonify({
                'success': True,
                'removed': True,
                'subtotal': subtotal,
                'discount': discount,
                'total': total
            })
    
    return redirect(url_for('cart'))

@app.route('/remove-from-cart/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    cart_item = Cart.query.get_or_404(item_id)
    db.session.delete(cart_item)
    db.session.commit()
    flash('প্রোডাক্ট কার্ট থেকে সরানো হয়েছে')
    return redirect(url_for('cart'))

# ========== কুপন সিস্টেম ==========
@app.route('/apply-coupon', methods=['POST'])
@login_required
def apply_coupon():
    code = request.form['coupon_code']
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    
    if not cart_items:
        return jsonify({'success': False, 'message': 'কার্ট খালি'})
    
    coupon = Coupon.query.filter_by(code=code).first()
    subtotal = sum(item.product.price * item.quantity for item in cart_items)
    
    if not coupon:
        return jsonify({'success': False, 'message': 'কুপন পাওয়া যায়নি'})
    
    now = datetime.utcnow()
    if now < coupon.valid_from or now > coupon.valid_to:
        return jsonify({'success': False, 'message': 'কুপন মেয়াদোত্তীর্ণ'})
    
    if subtotal < coupon.min_order:
        return jsonify({'success': False, 'message': f'ন্যূনতম অর্ডার ৳{coupon.min_order}'})
    
    if coupon.used_count >= coupon.usage_limit:
        return jsonify({'success': False, 'message': 'কুপন ব্যবহারের সীমা শেষ'})
    
    discount = (subtotal * coupon.discount_percent) / 100
    if coupon.max_discount > 0 and discount > coupon.max_discount:
        discount = coupon.max_discount
    
    total = subtotal - discount
    
    session['coupon_code'] = code
    session['discount'] = discount
    session['coupon_id'] = coupon.id
    
    return jsonify({
        'success': True,
        'discount': discount,
        'total': total,
        'message': f'ছাড় পেয়েছেন ৳{discount}'
    })

@app.route('/remove-coupon', methods=['POST'])
@login_required
def remove_coupon():
    session.pop('coupon_code', None)
    session.pop('discount', None)
    session.pop('coupon_id', None)
    
    return jsonify({'success': True})

# ========== চেকআউট ==========
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('আপনার কার্ট খালি')
        return redirect(url_for('products'))
    
    subtotal = sum(item.product.price * item.quantity for item in cart_items)
    discount = session.get('discount', 0)
    total = subtotal - discount
    
    if request.method == 'POST':
        payment_method = request.form['payment_method']
        coupon_id = session.get('coupon_id')
        coupon_code = session.get('coupon_code')
        
        order = Order(
            order_number=generate_order_number(),
            user_id=current_user.id,
            total_amount=subtotal,
            discount_amount=discount,
            coupon_code=coupon_code,
            final_amount=total,
            payment_method=payment_method,
            shipping_address=request.form['address'],
            phone=request.form['phone'],
            notes=request.form.get('notes', ''),
            status='pending',
            payment_status='pending'
        )
        db.session.add(order)
        db.session.flush()
        
        for item in cart_items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                product_name=item.product.name,
                price=item.product.price,
                quantity=item.quantity,
                total=item.product.price * item.quantity
            )
            db.session.add(order_item)
            
            item.product.stock -= item.quantity
            db.session.delete(item)
        
        if coupon_id:
            coupon = Coupon.query.get(coupon_id)
            if coupon:
                coupon.used_count += 1
        
        db.session.commit()
        
        session.pop('coupon_code', None)
        session.pop('discount', None)
        session.pop('coupon_id', None)
        
        flash('অর্ডার সফল হয়েছে! অর্ডার নম্বর: ' + order.order_number)
        return redirect(url_for('payment', order_id=order.id, method=payment_method))
    
    user = current_user
    
    return render_template('checkout.html', 
                         cart_items=cart_items, 
                         subtotal=subtotal,
                         discount=discount,
                         total=total,
                         user=user)

# ========== পেমেন্ট ==========
@app.route('/payment/<int:order_id>/<method>')
@login_required
def payment(order_id, method):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('এই অর্ডার আপনার নয়')
        return redirect(url_for('index'))
    
    return render_template(f'payment/{method}.html', order=order)

@app.route('/confirm-payment/<int:order_id>', methods=['POST'])
@login_required
def confirm_payment(order_id):
    order = Order.query.get_or_404(order_id)
    
    if order.user_id != current_user.id:
        flash('এই অর্ডার আপনার নয়')
        return redirect(url_for('index'))
    
    order.payment_number = request.form['payment_number']
    order.transaction_id = request.form['transaction_id']
    order.payment_status = 'pending'
    
    db.session.commit()
    
    flash('পেমেন্ট তথ্য জমা হয়েছে! এডমিন ভেরিফাই করার পর অর্ডার কনফার্ম হবে।')
    return redirect(url_for('orders'))

# ========== অর্ডার ==========
@app.route('/orders')
@login_required
def orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)

@app.route('/order/<int:id>')
@login_required
def order_detail(id):
    order = Order.query.get_or_404(id)
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('আপনি এই অর্ডার দেখতে পারবেন না')
        return redirect(url_for('index'))
    return render_template('order_detail.html', order=order)

@app.route('/invoice/<int:order_id>')
@login_required
def view_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('আপনি এই ইনভয়েস দেখতে পারবেন না')
        return redirect(url_for('index'))
    
    invoice = Invoice.query.filter_by(order_id=order_id).first()
    if not invoice:
        invoice_path = generate_invoice(order)
        invoice = Invoice(
            order_id=order.id,
            invoice_number=f"INV-{order.order_number}",
            pdf_path=invoice_path
        )
        db.session.add(invoice)
        db.session.commit()
    
    return send_file(os.path.join(app.config['INVOICE_FOLDER'], invoice.pdf_path))

def generate_invoice(order):
    """ইনভয়েস জেনারেট করার ফাংশন"""
    filename = f"invoice_{order.order_number}.pdf"
    filepath = os.path.join(app.config['INVOICE_FOLDER'], filename)
    
    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    title = Paragraph(f"ইনভয়েস #{order.order_number}", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 0.2*inch))
    
    customer_info = f"""
    <b>গ্রাহক:</b> {order.customer.username}<br/>
    <b>ইমেইল:</b> {order.customer.email}<br/>
    <b>ফোন:</b> {order.phone}<br/>
    <b>ঠিকানা:</b> {order.shipping_address}
    """
    story.append(Paragraph(customer_info, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    data = [['প্রোডাক্ট', 'দাম', 'পরিমাণ', 'মোট']]
    for item in order.items:
        data.append([item.product_name, f"৳{item.price}", str(item.quantity), f"৳{item.total}"])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    
    story.append(table)
    story.append(Spacer(1, 0.2*inch))
    
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
    ]))
    
    story.append(summary_table)
    doc.build(story)
    
    return filename

# ========== ট্র্যাকিং ==========
@app.route('/track-order/<order_number>')
def track_order(order_number):
    order = Order.query.filter_by(order_number=order_number).first()
    if not order:
        return render_template('track_order.html', error='অর্ডার পাওয়া যায়নি')
    
    tracking_info = {
        'status': order.status,
        'estimated_delivery': (order.created_at + timedelta(days=5)).strftime('%d %B, %Y'),
        'updates': [
            {'date': order.created_at.strftime('%d %B'), 'status': 'অর্ডার কনফার্ম হয়েছে'},
        ]
    }
    
    if order.status == 'shipped':
        tracking_info['updates'].append({'date': datetime.now().strftime('%d %B'), 'status': 'কুরিয়ারে পাঠানো হয়েছে'})
    elif order.status == 'delivered':
        tracking_info['updates'].append({'date': datetime.now().strftime('%d %B'), 'status': 'ডেলিভারি সম্পন্ন'})
    
    return render_template('track_order.html', order=order, tracking=tracking_info)

# ========== এডমিন রুটস ==========
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('এডমিন এলাকা')
        return redirect(url_for('index'))
    
    total_orders = Order.query.count()
    total_products = Product.query.count()
    total_users = User.query.count()
    total_revenue = db.session.query(db.func.sum(Order.final_amount)).filter_by(payment_status='paid').scalar() or 0
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_orders=total_orders,
                         total_products=total_products,
                         total_users=total_users,
                         total_revenue=total_revenue,
                         recent_orders=recent_orders)

@app.route('/admin/products')
@login_required
def admin_products():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('admin/products.html', products=products)

@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        old_price = float(request.form.get('old_price', 0))
        category = request.form['category']
        stock = int(request.form['stock'])
        featured = 'featured' in request.form
        discount_percent = float(request.form.get('discount_percent', 0))
        
        image = request.files['image']
        if image:
            filename = save_uploaded_file(image)
            
            product = Product(
                name=name,
                description=description,
                price=price,
                old_price=old_price,
                category=category,
                stock=stock,
                image=filename,
                featured=featured,
                discount_percent=discount_percent
            )
            
            db.session.add(product)
            db.session.commit()
            flash('প্রোডাক্ট যোগ হয়েছে')
            return redirect(url_for('admin_products'))
    
    return render_template('admin/add_product.html')

@app.route('/admin/products/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    product = Product.query.get_or_404(id)
    
    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.old_price = float(request.form.get('old_price', 0))
        product.category = request.form['category']
        product.stock = int(request.form['stock'])
        product.featured = 'featured' in request.form
        product.discount_percent = float(request.form.get('discount_percent', 0))
        
        image = request.files['image']
        if image:
            # পুরনো ছবি ডিলিট (শুধু লোকালে)
            if not is_vercel and product.image:
                old_file = os.path.join(app.config['UPLOAD_FOLDER'], product.image)
                if os.path.exists(old_file):
                    os.remove(old_file)
            
            filename = save_uploaded_file(image)
            product.image = filename
        
        db.session.commit()
        flash('প্রোডাক্ট আপডেট হয়েছে')
        return redirect(url_for('admin_products'))
    
    return render_template('admin/edit_product.html', product=product)

@app.route('/admin/products/delete/<int:id>')
@login_required
def delete_product(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    product = Product.query.get_or_404(id)
    
    # পুরনো ছবি ডিলিট (শুধু লোকালে)
    if not is_vercel and product.image:
        old_file = os.path.join(app.config['UPLOAD_FOLDER'], product.image)
        if os.path.exists(old_file):
            os.remove(old_file)
    
    db.session.delete(product)
    db.session.commit()
    flash('প্রোডাক্ট ডিলিট হয়েছে')
    return redirect(url_for('admin_products'))

@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/orders/update/<int:id>', methods=['POST'])
@login_required
def update_order_status(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    order = Order.query.get_or_404(id)
    order.status = request.form['status']
    
    if 'tracking_number' in request.form:
        order.tracking_number = request.form['tracking_number']
    if 'courier_name' in request.form:
        order.courier_name = request.form['courier_name']
    
    db.session.commit()
    flash('অর্ডার স্ট্যাটাস আপডেট হয়েছে')
    return redirect(url_for('admin_orders'))

@app.route('/admin/verify-payment/<int:order_id>', methods=['POST'])
@login_required
def verify_payment(order_id):
    if not current_user.is_admin:
        flash('এডমিন এলাকা')
        return redirect(url_for('index'))
    
    order = Order.query.get_or_404(order_id)
    action = request.form['action']
    
    if action == 'approve':
        order.payment_status = 'paid'
        order.status = 'confirmed'
        flash(f'অর্ডার #{order.order_number} এর পেমেন্ট অ্যাপ্রুভ হয়েছে')
        generate_invoice(order)
    elif action == 'reject':
        order.payment_status = 'failed'
        order.status = 'pending'
        flash(f'অর্ডার #{order.order_number} এর পেমেন্ট রিজেক্ট করা হয়েছে')
    
    db.session.commit()
    return redirect(url_for('admin_orders'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/coupons')
@login_required
def admin_coupons():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    coupons = Coupon.query.order_by(Coupon.created_at.desc()).all()
    return render_template('admin/coupons.html', coupons=coupons)

@app.route('/admin/coupons/add', methods=['GET', 'POST'])
@login_required
def add_coupon():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        coupon = Coupon(
            code=request.form['code'],
            discount_percent=float(request.form['discount_percent']),
            min_order=float(request.form.get('min_order', 0)),
            max_discount=float(request.form.get('max_discount', 0)),
            valid_from=datetime.strptime(request.form['valid_from'], '%Y-%m-%d'),
            valid_to=datetime.strptime(request.form['valid_to'], '%Y-%m-%d'),
            usage_limit=int(request.form.get('usage_limit', 1))
        )
        db.session.add(coupon)
        db.session.commit()
        flash('কুপন যোগ হয়েছে')
        return redirect(url_for('admin_coupons'))
    
    return render_template('admin/add_coupon.html')

@app.route('/admin/profile/edit', methods=['GET', 'POST'])
@login_required
def admin_profile_edit():
    if not current_user.is_admin:
        flash('এডমিন এলাকা')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current_user.username = request.form['username']
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        current_user.address = request.form['address']
        
        new_password = request.form.get('new_password')
        if new_password:
            current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        db.session.commit()
        flash('প্রোফাইল আপডেট হয়েছে!')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/profile_edit.html', user=current_user)

# ========== রিপোর্ট ==========
@app.route('/admin/report/orders/<format>')
@login_required
def order_report(format):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    orders = Order.query.all()
    data = []
    
    for order in orders:
        data.append({
            'অর্ডার নম্বর': order.order_number,
            'গ্রাহক': order.customer.username,
            'মোট': order.total_amount,
            'ছাড়': order.discount_amount,
            'সর্বমোট': order.final_amount,
            'পেমেন্ট': order.payment_method,
            'পেমেন্ট স্ট্যাটাস': order.payment_status,
            'স্ট্যাটাস': order.status,
            'তারিখ': order.created_at.strftime('%Y-%m-%d')
        })
    
    df = pd.DataFrame(data)
    filename = f'orders_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    
    if format == 'excel':
        filepath = os.path.join(app.config['REPORT_FOLDER'], f'{filename}.xlsx')
        df.to_excel(filepath, index=False)
        return send_file(filepath, as_attachment=True)
    
    elif format == 'pdf':
        filepath = os.path.join(app.config['REPORT_FOLDER'], f'{filename}.pdf')
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        elements = []
        
        styles = getSampleStyleSheet()
        title = Paragraph("অর্ডার রিপোর্ট", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        table_data = [list(df.columns)] + df.values.tolist()
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        
        return send_file(filepath, as_attachment=True)

# ========== মেইন ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # এডমিন ইউজার তৈরি করুন
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@shop.com',
                password_hash=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                phone='01700000000',
                is_admin=True,
                phone_verified=True,
                email_verified=True
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ এডমিন ইউজার তৈরি হয়েছে: admin / admin123")
        
        # স্যাম্পল কুপন
        if Coupon.query.count() == 0:
            coupons = [
                Coupon(
                    code='WELCOME10',
                    discount_percent=10,
                    min_order=500,
                    max_discount=200,
                    valid_from=datetime.now(),
                    valid_to=datetime.now() + timedelta(days=30),
                    usage_limit=100
                ),
                Coupon(
                    code='SAVE20',
                    discount_percent=20,
                    min_order=1000,
                    max_discount=500,
                    valid_from=datetime.now(),
                    valid_to=datetime.now() + timedelta(days=15),
                    usage_limit=50
                )
            ]
            db.session.add_all(coupons)
            db.session.commit()
            print("✅ স্যাম্পল কুপন যোগ হয়েছে")
        
        # স্যাম্পল প্রোডাক্ট
        if Product.query.count() == 0:
            products = [
                Product(
                    name='স্মার্টফোন',
                    description='৬জিবি র‍্যাম, ১২৮জিবি স্টোরেজ',
                    price=25000,
                    old_price=30000,
                    category='ইলেকট্রনিক্স',
                    stock=10,
                    featured=True
                ),
                Product(
                    name='টি-শার্ট',
                    description='কটন প্রিন্টেড টি-শার্ট',
                    price=500,
                    old_price=800,
                    category='ফ্যাশন',
                    stock=50,
                    featured=True
                ),
                Product(
                    name='কুকিং অয়েল',
                    description='৫ লিটার সয়াবিন তেল',
                    price=800,
                    old_price=1000,
                    category='গৃহস্থালি',
                    stock=30,
                    featured=True
                )
            ]
            db.session.add_all(products)
            db.session.commit()
            print("✅ স্যাম্পল প্রোডাক্ট যোগ হয়েছে")
    
    app.run(debug=True)