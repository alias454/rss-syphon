FROM python:3.10.7-alpine

COPY src /app
COPY entrypoint.sh /app/entrypoint.sh

WORKDIR /app

RUN chmod +x entrypoint.sh \
 && pip install --root-user-action=ignore --upgrade pip \
 && python -m pip install --root-user-action=ignore -r requirements.txt

ENTRYPOINT ["./entrypoint.sh"]
