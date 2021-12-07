# [START docker]

FROM python:3.9

# Create a virtualenv for the application dependencies.
RUN python3 --version
RUN python3 -m venv /venv
ENV PATH /venv/bin:$PATH

ADD requirements.txt /app/requirements.txt
RUN /venv/bin/pip install --upgrade pip && /venv/bin/pip install -r /app/requirements.txt
ADD . /app

WORKDIR /app

CMD gunicorn --error-logfile - --log-file - -b :$PORT wclient_test.wsgi


# [END docker]