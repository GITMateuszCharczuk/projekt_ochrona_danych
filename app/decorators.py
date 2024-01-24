from functools import wraps
from flask import request, flash, redirect, url_for
from app.models import Client, Request
from app import db
from datetime import datetime, timedelta
import sys
import time

def check_client(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        client_ip = request.remote_addr
        client = Client.query.filter_by(ip=client_ip).first()
        if client:
            if client.is_suspended and datetime.utcnow() >= client.timeout_date:
                client.is_suspended = False
            else:
                flash('Account suspended for too many requests', 'danger')
                return redirect(url_for('routes.home'))

            time_difference = datetime.utcnow() - client.requests[-1].request_date if client.requests else timedelta(seconds=1)
            if time_difference.total_seconds() < 1:
                time.sleep(1)

            recent_requests = Client.query.filter(
                Client.ip == client_ip,
                Client.requests.any(Request.request_date >= (datetime.utcnow() - timedelta(minutes=1)))
            ).count()

            if recent_requests >= 3:
                client.is_suspended = True
                client.timeout_date = datetime.utcnow() + timedelta(minutes=1) # hours=1
                db.session.commit()
                flash('Account suspended for too many requests', 'danger')
                return redirect(url_for('routes.home'))

        if client:
            request_entry = Request(client_id=client.id)
            db.session.add(request_entry)
            db.session.commit()

        return func(*args, **kwargs)

    return wrapper