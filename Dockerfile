FROM python:3.12.0-alpine

WORKDIR /src

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY /src .

COPY crontab crontab

RUN crontab crontab

CMD ["crond", "&&", "tail", "-f", "/logfile"]