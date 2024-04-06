FROM ubuntu:latest AS builder
WORKDIR /root/att_doc_retriever_sample/rs/
ARG ARCH

# Ensure the architecture is set
RUN if [ -n "${ARCH}" ]; \
    then echo "Will target architecture \"${ARCH}\"."; \
    else echo "Target architecture not specified. Will exit."; exit 1; \
    fi

COPY rs .

RUN apt-get update && apt-get install gcc curl -y

# Get Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target install ${ARCH}-unknown-linux-musl

# Build the Rust application
RUN cargo build --release --target=${ARCH}-unknown-linux-musl

#FROM public.ecr.aws/docker/library/python:3.7.9-alpine3.12
FROM python:3.7.11-slim-buster
ARG ARCH

# Copy the Rust compiled binary from previous image
COPY --from=builder /root/att_doc_retriever_sample/rs/target/${ARCH}-unknown-linux-musl/release/att_doc_retriever_sample .

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

