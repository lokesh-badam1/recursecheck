FROM python:3.12-slim
RUN pip install --no-cache-dir dnslib
COPY decoy.py /decoy.py
CMD ["python", "-u", "/decoy.py"]
