FROM python:3.12-alpine
RUN apk add --no-cache iproute2
WORKDIR /app
COPY check.py .
EXPOSE 3478
CMD ["python3", "check.py"]

