#FROM public.ecr.aws/docker/library/python:3.7.9-alpine3.12
FROM python:3.7.11-slim-buster

# Set the working directory in the container
# WORKDIR /app

# Copy requirements.txt file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy required files into the container
COPY tls_client.py .
COPY certificates.py .
COPY cipher_suites.py .
COPY constants.py .
COPY ec_curves.py .
COPY extensions.py .
COPY key_exchange.py .
COPY packer.py .
COPY prf.py .
COPY print_colors.py .
COPY reader.py .
COPY signature_algorithms.py .
COPY tls.py .
COPY encryption_algorithms.py .
# Copy the server.py file into the container
COPY server_aws.py server.py

CMD ["/usr/local/bin/python3", "server.py", "5001"]

