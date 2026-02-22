from app import app, db
from models import Order

with app.app_context():
    for order in Order.query.all():
        if not hasattr(order, 'payment_status'):
            order.payment_status = 'pending'
    db.session.commit()
    print("✅ ডাটাবেস আপডেট হয়েছে")