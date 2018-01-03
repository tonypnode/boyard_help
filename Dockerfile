FROM ubuntu:16.04


RUN apt-get update \
 && apt-get install -y locales \
 && apt-get install -y python3.5 python3-pip libffi-dev libssl-dev

WORKDIR /opt/sec_check
COPY requirements.txt requirements.txt
COPY security_check.py security_check.py
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN python3 security_check.py
