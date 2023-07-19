FROM python:3.9

WORKDIR /yara-app

COPY requirements.txt .
COPY ./app ./app

RUN apt-get update
RUN apt-get install -y magic libmagic1 
RUN pip install -r requirements.txt
RUN mkdir static
RUN mkdir -p static/uploads
RUN mkdir -p static/yara-rules

CMD ["python", "./app/main.py"]

