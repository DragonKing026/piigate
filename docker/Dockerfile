# piigate container engine: Presidio Analyzer (Data Privacy Stack) + Polish spaCy model, built on YOUR machine.
#
# The image is never published: pl_core_news_lg is licensed GPL-3.0 (see README, "Model license"); you download it
# here, at build time, from explosion/spacy-models and the build checks its sha256. piigate itself stays MIT.
#
#   docker build -t piigate-presidio:2.2.366 docker/
#   docker run -d --name piigate-presidio --network none ...   # see README, "Container engine"
#
# Final stage is the distroless variant (no shell, no pip): the model is unpacked in a builder stage based on the
# regular image of the same release, then copied in. Both bases are pinned by digest.
ARG BUILDER=ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366@sha256:036d2f9b3c274fb36497383acef8f2d5aea528a014801c2c3040fb067990c79c
ARG BASE=ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366-distroless@sha256:84cb78c12a26d7ff4d2f5b980452dd9983c0a5c8c56ee410226bb6bb3f19f7d8

FROM ${BUILDER} AS model
ARG PL_MODEL_URL=https://github.com/explosion/spacy-models/releases/download/pl_core_news_lg-3.8.0/pl_core_news_lg-3.8.0-py3-none-any.whl
ARG PL_MODEL_SHA256=3bc7296cd4d67fa9ee0904b25401b0e9a9a772d5c4756edf54143a2ff4c9dcc0
USER root
RUN python -c "import urllib.request; urllib.request.urlretrieve('${PL_MODEL_URL}', '/tmp/pl_core_news_lg-3.8.0-py3-none-any.whl')" \
 && echo "${PL_MODEL_SHA256}  /tmp/pl_core_news_lg-3.8.0-py3-none-any.whl" | sha256sum -c - \
 && pip install --no-deps --no-compile --target /out /tmp/pl_core_news_lg-3.8.0-py3-none-any.whl

FROM ${BASE}
COPY --from=model /out/ /usr/lib/python3.12/site-packages/
COPY analyzer.yaml /app/piigate/analyzer.yaml
ENV ANALYZER_CONF_FILE=/app/piigate/analyzer.yaml \
    NLP_CONF_FILE= \
    RECOGNIZER_REGISTRY_CONF_FILE=
