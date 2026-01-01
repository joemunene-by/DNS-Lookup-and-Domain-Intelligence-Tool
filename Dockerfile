FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install flask dnspython python-whois

EXPOSE 5000

CMD ["python", "web_dns_lookup.py"]
