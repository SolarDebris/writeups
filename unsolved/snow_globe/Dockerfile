# Ubuntu 24.04
# GCC 13.2.0
# Clang 18.0
# GLIBC 2.39

###############
# Base system #
###############
FROM docker.io/library/ubuntu@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15 AS base

# Install apt dependencies if needed
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y python3 python3-pip python3-venv coreutils webp libmagickcore-6.q16-7t64 libseccomp2 libcap2-bin && apt-get clean
COPY policy.xml /etc/ImageMagick-6/policy.xml

# Enable the virtual enviroment
RUN python3 -m venv /.venv
ENV PATH="/.venv/bin:$PATH"

# Install pip dependencies
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt 

RUN groupadd -g 1337 extractor && \
    groupadd -g 1338 globe && \
    useradd -M -u 1001 -U -G extractor,globe ctf

# Copy challenge required files
RUN mkdir -p /app

COPY ./challenge /app/challenge
COPY ./flag.txt /flag.txt
COPY ./entrypoint.sh /app/entrypoint.sh
COPY ./static /app/static
COPY ./templates /app/templates
COPY ./snow_globe /app/snow_globe
COPY ./extractor /app/extractor
COPY ./globe_wrapper /app/globe_wrapper
COPY ./globe.png /app/globe.png
COPY ./flag.png /flag.png

RUN chmod +x /app/challenge && \
    chown 1337:1337 /app/extractor && \
    chmod ug+s,-w /app/extractor && \
    ln -s /tmp/snow_globe/results /app/static/results

USER 1001
CMD /app/entrypoint.sh
