FROM python:3.9


WORKDIR /yara-app

COPY requirements.txt .

RUN apt-get update
RUN apt-get install -y magic libmagic1 
RUN pip install -r requirements.txt

COPY ./app ./app
COPY ./static ./static

CMD ["python", "./app/main.py"]

