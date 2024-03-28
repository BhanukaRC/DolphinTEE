#FROM public.ecr.aws/docker/library/python:3.7.9-alpine3.12
FROM python:3.7.11-slim-buster

# Set the working directory in the container
# WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy the server.py file into the container
COPY server_aws.py server.py

CMD ["/usr/local/bin/python3", "server.py", "5001"]

