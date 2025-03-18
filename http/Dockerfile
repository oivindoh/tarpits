FROM debian:12-slim AS build
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3 python3-venv curl ca-certificates && \
    python3 -m venv /venv && \
    curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/uv && \
    rm -rf /root/.local

FROM build AS build-venv
COPY requirements.txt /requirements.txt
RUN . /venv/bin/activate && uv pip install --disable-pip-version-check -r /requirements.txt

FROM gcr.io/distroless/python3-debian12
COPY --from=build-venv /venv /venv
COPY http-teepee.py /
ENV PYTHONUNBUFFERED=1
WORKDIR /
EXPOSE 2222/tcp
USER 65532
ENTRYPOINT [ "/venv/bin/python3", "/http-teepee.py", "-a", "0.0.0.0" ]
