FROM apache/airflow:2.1.4-python3.8

# Change container image to root user to allow for global
# installation of software
USER root
RUN apt-get update && apt-get install -y git \
    && pip3 install --upgrade pip

# Install dependencies needed for OpenID connect authentication.
# These pip, requests, and flasks-oidc. The packages are installed
# within the user context.
USER airflow
RUN pip3 install requests flask-oidc aiohttp

# Copy the OIDC webserver_config.py into the container's $AIRFLOW_HOME
COPY webserver_config.py $AIRFLOW_HOME/webserver_config.py