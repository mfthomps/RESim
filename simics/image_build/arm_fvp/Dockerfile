# syntax=docker/dockerfile:1

FROM ubuntu:18.04

# Avoid timezone prompts when installing packages
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

# Update package lists and install necessary packages
RUN apt-get update && apt-get install -y \
    sudo \
    python3 \
    python3-pip  \
    git \
    cpio \ 
    diffstat \
    gawk \
    wget \
    chrpath \
    language-pack-en-base 

RUN pip3 install --upgrade pip

# Copy files
COPY requirements.txt .
COPY install_apt.sh .
COPY README .

# Install packages/dependencies with requirements.txt and install_apt.sh
RUN pip3 install -r requirements.txt
RUN bash install_apt.sh

# Create non-root user with sudo access
RUN useradd -m john && echo "john:john" | chpasswd && adduser john sudo
USER john
