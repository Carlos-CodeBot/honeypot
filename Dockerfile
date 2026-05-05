FROM python:3.12-slim
WORKDIR /app
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app /app
RUN mkdir -p /data
EXPOSE 8000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]