from functools import wraps
from flask import request, flash, redirect, url_for
from app.models import Client, Request
from app import db
from datetime import datetime, timedelta
from sqlalchemy.orm import aliased
import time

def check_client(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr

        client = Client.query.filter_by(ip=client_ip).first()
        
        if not client:
            client = Client(ip=client_ip)
            db.session.add(client)
            db.session.commit()
        
        if client:
            request_entry = Request(client_id=client.id)
            client.requests.append(request_entry)
            db.session.add(request_entry)
            db.session.commit()
    
            if client.is_suspended and datetime.utcnow() >= client.timeout_date:
                client.is_suspended = False
            elif client.is_suspended:
                flash('Account suspended for too many requests', 'danger')
                return redirect(url_for('routes.home'))

            time_difference = datetime.utcnow() - client.requests[-1].request_date if client.requests else timedelta(seconds=1)
            if time_difference.total_seconds() < 1:
                time.sleep(1)

            request_alias = aliased(Request)

            recent_requests = (
                Client.query
                .join(request_alias, Client.requests)
                .filter(
                    Client.ip == client_ip,
                    request_alias.request_date.between(
                        (datetime.utcnow() - timedelta(minutes=10)),
                        datetime.utcnow()
                    )
                )
                .count()
            )

            if recent_requests >= 100:
                client.is_suspended = True
                client.timeout_date = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()
                flash('Account suspended for too many requests', 'danger')
                return redirect(url_for('routes.home'))
        return func(*args, **kwargs)

    return wrapper