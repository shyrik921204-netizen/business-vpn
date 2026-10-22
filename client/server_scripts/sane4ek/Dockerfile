FROM python:3.12-alpine

LABEL maintainer="Sane4ek"

RUN apk add --no-cache docker-cli openssl
COPY agent.py /agent.py

EXPOSE 47443/tcp
ENTRYPOINT ["python3", "-u", "/agent.py"]
