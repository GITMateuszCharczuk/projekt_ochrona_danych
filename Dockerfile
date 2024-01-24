# Dockerfile

FROM python:3.8-slim-buster

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

# Run migrations
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["bash", "/usr/local/bin/entrypoint.sh"]

# Ustawiamy zmienną środowiskową dla Flask
ENV FLASK_APP=app.py

EXPOSE 5000

COPY nginx.conf /etc/nginx/conf.d/default.conf

# Uruchamiamy aplikację
CMD ["flask", "run", "--host=0.0.0.0"]
